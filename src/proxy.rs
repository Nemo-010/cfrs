//! Inbound tunnel streams: parse the edge framing and dispatch to a service.
//!
//! One QUIC stream carries one request. After the `ConnectRequest` preamble the
//! stream is either HTTP (we synthesise an HTTP/1.1 request for the origin and
//! relay the response) or raw TCP (byte pump). Built-in services are axum
//! routers called directly, so multipart, directory serving and file transfer
//! work without an external process.

use anyhow::{anyhow, bail, Context, Result};
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, Response};
use cloudflare_quick_tunnel::stream as cqstream;
use cloudflare_quick_tunnel::stream::{HTTP_HEADER_KEY, HTTP_HOST_KEY, HTTP_METHOD_KEY};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};
use tower::ServiceExt;

use crate::gate::UNLOCK_PATH;
use crate::ingress::{Ingress, OriginOptions, Service};
use crate::metrics::Metrics;
use crate::net::{self, BoxedIo};
use crate::service::{Built, ServiceRuntime};
use crate::share::ShareControl;
use crate::util::path_and_query;

const MAX_HEAD_BYTES: usize = 32 * 1024;

pub(crate) type EdgeReader = Compat<quinn::RecvStream>;
pub(crate) type EdgeWriter = Compat<quinn::SendStream>;

/// Handle one inbound stream. Errors are logged, never propagated to the edge.
pub async fn serve_stream(
    runtime: std::sync::Arc<ServiceRuntime>,
    ingress: std::sync::Arc<Ingress>,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
) {
    let metrics = runtime.metrics().clone();
    metrics.stream_started();
    if let Err(err) = serve_inner(&runtime, &ingress, send, recv).await {
        metrics.error();
        tracing::warn!(error = %err, "stream failed");
    }
    metrics.stream_finished();
}

async fn serve_inner(
    runtime: &ServiceRuntime,
    ingress: &Ingress,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
) -> Result<()> {
    let (mut reader, writer) = cqstream::split(send, recv);
    let request = cqstream::read_connect_request(&mut reader).await?;
    let host = request
        .meta(HTTP_HOST_KEY)
        .map(str::to_string)
        .or_else(|| crate::util::authority_of(&request.dest))
        .unwrap_or_default();
    let path = path_and_query(&request.dest);
    tracing::debug!(%host, %path, kind = ?request.conn_type, "inbound");

    let Some(index) = ingress.resolve_index(&host, &path) else {
        let mut writer = writer;
        return write_simple_response(
            &mut writer,
            503,
            "text/plain; charset=utf-8",
            b"cfrs: no ingress rule matched\n",
        )
        .await;
    };
    let built = runtime.get(index).context("runtime rule missing")?;

    match built {
        Built::Forward(service, options) => {
            forward_http(service, options, &request, reader, writer, runtime.metrics()).await
        }
        Built::Tcp(service, options) => {
            forward_tcp(service, options, &request, reader, writer, runtime.metrics()).await
        }
        Built::ForwardWs(target) => {
            if !is_websocket(&request) {
                let mut writer = writer;
                return write_simple_response(
                    &mut writer,
                    426,
                    "text/plain; charset=utf-8",
                    b"cfrs: this endpoint requires a WebSocket upgrade\n",
                )
                .await;
            }
            crate::ws::serve_websocket(target, &request, reader, writer, runtime.metrics()).await
        }
        Built::HelloWorld => {
            let mut writer = writer;
            write_simple_response(
                &mut writer,
                200,
                "text/plain; charset=utf-8",
                b"Hello, world! (cfrs)\n",
            )
            .await
        }
        Built::Status(code) => {
            let mut writer = writer;
            write_simple_response(&mut writer, *code, "text/plain; charset=utf-8", b"").await
        }
        Built::Metrics => {
            let text = runtime.metrics().prometheus();
            let mut writer = writer;
            write_simple_response(
                &mut writer,
                200,
                "text/plain; version=0.0.4; charset=utf-8",
                text.as_bytes(),
            )
            .await
        }
        Built::Static(router) => {
            dispatch_axum(router.clone(), &request, &host, reader, writer, runtime.metrics()).await
        }
        Built::Share(app) => {
            dispatch_axum(app.router(), &request, &host, reader, writer, runtime.metrics()).await
        }
        Built::ShareProxy {
            target,
            gate,
            control,
        } => {
            share_proxy(
                target,
                gate,
                control,
                &request,
                &host,
                reader,
                writer,
                runtime.metrics(),
            )
            .await
        }
    }
}

// ── HTTP forwarding ─────────────────────────────────────────────────────────

async fn forward_http(
    service: &Service,
    options: &OriginOptions,
    request: &cqstream::ConnectRequest,
    mut reader: EdgeReader,
    mut writer: EdgeWriter,
    metrics: &Metrics,
) -> Result<()> {
    let mut io = net::dial(service, options).await?;
    let upgrade = is_upgrade(request);
    let head = build_request_head(request, options, upgrade);
    tokio::io::AsyncWriteExt::write_all(&mut io, head.as_bytes()).await?;

    if upgrade || is_chunked(request) {
        return proxy_bidi(&mut reader, &mut writer, io, metrics).await;
    }

    if let Some(len) = content_length(request) {
        if len > 0 {
            copy_futures_to_tokio_n(&mut reader, &mut io, len, metrics).await?;
        }
    }

    let (status, headers, leftover) = read_response_head(&mut io).await?;
    write_response_meta(&mut writer, status, &headers).await?;
    if !leftover.is_empty() {
        futures_write_all(&mut writer, &leftover).await?;
        metrics.add_out(leftover.len() as u64);
    }
    let resp_len = headers_value(&headers, "content-length").and_then(|v| v.parse::<u64>().ok());
    match resp_len {
        Some(total) => {
            let remaining = total.saturating_sub(leftover.len() as u64);
            if remaining > 0 {
                copy_tokio_to_futures_n(&mut io, &mut writer, remaining, metrics).await?;
            }
        }
        None => {
            copy_tokio_to_futures_eof(&mut io, &mut writer, metrics).await?;
        }
    }
    futures_close(&mut writer).await
}

async fn proxy_bidi(
    reader: &mut EdgeReader,
    writer: &mut EdgeWriter,
    io: BoxedIo,
    metrics: &Metrics,
) -> Result<()> {
    let (mut io_r, mut io_w) = tokio::io::split(io);
    let in_metrics = metrics.clone();
    let out_metrics = metrics.clone();

    let request_pump = async {
        let _ = copy_futures_to_tokio_eof(reader, &mut io_w, &in_metrics).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut io_w).await;
    };
    let response_pump = async {
        let (status, headers, leftover) = read_response_head(&mut io_r).await?;
        write_response_meta(writer, status, &headers).await?;
        if !leftover.is_empty() {
            futures_write_all(writer, &leftover).await?;
            out_metrics.add_out(leftover.len() as u64);
        }
        copy_tokio_to_futures_eof(&mut io_r, writer, &out_metrics).await?;
        futures_close(writer).await?;
        Ok::<(), anyhow::Error>(())
    };
    let (_, response) = tokio::join!(request_pump, response_pump);
    response
}

async fn forward_tcp(
    service: &Service,
    options: &OriginOptions,
    _request: &cqstream::ConnectRequest,
    mut reader: EdgeReader,
    mut writer: EdgeWriter,
    metrics: &Metrics,
) -> Result<()> {
    let io = net::dial(service, options).await?;
    cqstream::write_connect_response(&mut writer, "", &[]).await?;
    let (mut io_r, mut io_w) = tokio::io::split(io);
    let in_metrics = metrics.clone();
    let out_metrics = metrics.clone();
    let to_origin = async {
        let _ = copy_futures_to_tokio_eof(&mut reader, &mut io_w, &in_metrics).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut io_w).await;
    };
    let from_origin = async {
        let _ = copy_tokio_to_futures_eof(&mut io_r, &mut writer, &out_metrics).await;
        let _ = futures_close(&mut writer).await;
    };
    tokio::join!(to_origin, from_origin);
    Ok(())
}

// ── Built-in (axum) dispatch ────────────────────────────────────────────────

async fn dispatch_axum(
    router: axum::Router,
    request: &cqstream::ConnectRequest,
    host: &str,
    reader: EdgeReader,
    mut writer: EdgeWriter,
    metrics: &Metrics,
) -> Result<()> {
    let uri = path_and_query(&request.dest);
    let method = request.meta(HTTP_METHOD_KEY).unwrap_or("GET");
    let builder = Request::builder().method(method).uri(uri);

    let mut headers = HeaderMap::new();
    for (key, value) in &request.metadata {
        let Some(name) = key.strip_prefix(&format!("{HTTP_HEADER_KEY}:")) else {
            continue;
        };
        if is_hop_by_hop(name) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.append(name, value);
        }
    }
    if !headers.contains_key(axum::http::header::HOST) && !host.is_empty() {
        if let Ok(value) = HeaderValue::from_str(host) {
            headers.insert(axum::http::header::HOST, value);
        }
    }

    let body = Body::from_stream(tokio_util::io::ReaderStream::new(reader.compat()));
    let mut axum_request = builder.body(body)?;
    *axum_request.headers_mut() = headers;

    let response: Response<Body> = router
        .oneshot(axum_request)
        .await
        .map_err(|e| anyhow!("service error: {e}"))?;

    write_axum_response(&mut writer, response, metrics).await
}

async fn write_axum_response(
    writer: &mut EdgeWriter,
    response: Response<Body>,
    metrics: &Metrics,
) -> Result<()> {
    let status = response.status().as_u16();
    let mut headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();

    let has_len = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length"));
    let has_chunked = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
    });

    let body = response.into_body();
    if !has_len && !has_chunked {
        // Small built-in bodies: buffer so the edge gets a Content-Length.
        let bytes = http_body_util::BodyExt::collect(body)
            .await
            .map_err(|e| anyhow!("reading response body: {e}"))?
            .to_bytes();
        headers.push(("Content-Length".to_string(), bytes.len().to_string()));
        write_response_meta(writer, status, &headers).await?;
        futures_write_all(writer, &bytes).await?;
        metrics.add_out(bytes.len() as u64);
    } else {
        write_response_meta(writer, status, &headers).await?;
        use futures::StreamExt;
        let mut stream = body.into_data_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| anyhow!("response body: {e}"))?;
            futures_write_all(writer, &chunk).await?;
            metrics.add_out(chunk.len() as u64);
        }
    }
    futures_close(writer).await
}

// ── quickbridge proxy mode ──────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn share_proxy(
    target: &str,
    gate: &crate::gate::Gate,
    control: &ShareControl,
    request: &cqstream::ConnectRequest,
    _host: &str,
    mut reader: EdgeReader,
    mut writer: EdgeWriter,
    metrics: &Metrics,
) -> Result<()> {
    let path = path_and_query(&request.dest);
    let method = request.meta(HTTP_METHOD_KEY).unwrap_or("GET");
    let headers = headers_from_request(request);

    if path == UNLOCK_PATH && method.eq_ignore_ascii_case("POST") {
        let body = read_body(&mut reader, content_length(request).unwrap_or(0)).await?;
        let fields = parse_form(&body);
        let password = fields
            .iter()
            .find(|(k, _)| k == "password")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let next = fields
            .iter()
            .find(|(k, _)| k == "next")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "/".to_string());
        return match gate.unlock(&password) {
            Some(cookie) => {
                write_simple_response_with(
                    &mut writer,
                    303,
                    "text/plain; charset=utf-8",
                    b"",
                    &[
                        ("Location".to_string(), sanitize_next(&next)),
                        ("Set-Cookie".to_string(), cookie),
                    ],
                )
                .await
            }
            None => {
                let html = gate.page_html(&next, true);
                write_simple_response(
                    &mut writer,
                    200,
                    "text/html; charset=utf-8",
                    html.as_bytes(),
                )
                .await
            }
        };
    }

    if !gate.is_open(&headers) {
        let html = gate.page_html(&path, false);
        return write_simple_response(
            &mut writer,
            200,
            "text/html; charset=utf-8",
            html.as_bytes(),
        )
        .await;
    }

    control.touch();
    let service = Service::Http(format!("http://{target}"));
    forward_http(
        &service,
        &OriginOptions::default(),
        request,
        reader,
        writer,
        metrics,
    )
    .await
}

fn sanitize_next(next: &str) -> String {
    if next.starts_with('/') && !next.starts_with("//") {
        next.to_string()
    } else {
        "/".to_string()
    }
}

fn headers_from_request(request: &cqstream::ConnectRequest) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (key, value) in &request.metadata {
        let Some(name) = key.strip_prefix(&format!("{HTTP_HEADER_KEY}:")) else {
            continue;
        };
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.append(name, value);
        }
    }
    headers
}

async fn read_body(reader: &mut EdgeReader, len: u64) -> Result<Vec<u8>> {
    let mut body = vec![0u8; len as usize];
    if len > 0 {
        futures::io::AsyncReadExt::read_exact(reader, &mut body).await?;
    }
    Ok(body)
}

fn parse_form(body: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(body);
    text.split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((percent_decode(key), percent_decode(value)))
        })
        .collect()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    index += 3;
                } else {
                    out.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ── Response helpers ────────────────────────────────────────────────────────

async fn write_simple_response(
    writer: &mut EdgeWriter,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    write_simple_response_with(writer, status, content_type, body, &[]).await
}

async fn write_simple_response_with(
    writer: &mut EdgeWriter,
    status: u16,
    content_type: &str,
    body: &[u8],
    extra: &[(String, String)],
) -> Result<()> {
    let mut headers = vec![
        ("Content-Type".to_string(), content_type.to_string()),
        ("Content-Length".to_string(), body.len().to_string()),
    ];
    headers.extend(extra.iter().cloned());
    write_response_meta(writer, status, &headers).await?;
    if !body.is_empty() {
        futures_write_all(writer, body).await?;
    }
    futures_close(writer).await
}

/// Build the `ConnectResponse` metadata pairs. The status is a bare
/// `HttpStatus`; every header must be `HttpHeader:<Name>` or the edge drops it.
fn response_meta_pairs(status: u16, headers: &[(String, String)]) -> Vec<(String, String)> {
    let prefix = format!("{HTTP_HEADER_KEY}:");
    let mut meta: Vec<(String, String)> = Vec::with_capacity(headers.len() + 1);
    meta.push((cqstream::HTTP_STATUS_KEY.to_string(), status.to_string()));
    for (name, value) in headers {
        let key = if name == cqstream::HTTP_STATUS_KEY || name.starts_with(&prefix) {
            name.clone()
        } else {
            format!("{prefix}{name}")
        };
        meta.push((key, value.clone()));
    }
    meta
}

pub(crate) async fn write_response_meta(
    writer: &mut EdgeWriter,
    status: u16,
    headers: &[(String, String)],
) -> Result<()> {
    let meta = response_meta_pairs(status, headers);
    let refs: Vec<(&str, &str)> = meta.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    cqstream::write_connect_response(writer, "", &refs).await?;
    Ok(())
}

// ── Request head ────────────────────────────────────────────────────────────

fn build_request_head(
    request: &cqstream::ConnectRequest,
    options: &OriginOptions,
    upgrade: bool,
) -> String {
    let method = request.meta(HTTP_METHOD_KEY).unwrap_or("GET");
    let path = request_path(&request.dest);
    let host = options
        .http_host_header
        .clone()
        .or_else(|| request.meta(HTTP_HOST_KEY).map(str::to_string))
        .unwrap_or_default();
    let prefix = format!("{HTTP_HEADER_KEY}:");

    let mut head = String::with_capacity(256);
    head.push_str(method);
    head.push(' ');
    head.push_str(&path);
    head.push_str(" HTTP/1.1\r\n");
    if !host.is_empty() {
        head.push_str("Host: ");
        head.push_str(&host);
        head.push_str("\r\n");
    }
    let mut saw_connection = false;
    for (key, value) in &request.metadata {
        let Some(name) = key.strip_prefix(&prefix) else {
            continue;
        };
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        if options.strip_accept_encoding && name.eq_ignore_ascii_case("accept-encoding") {
            continue;
        }
        if name.eq_ignore_ascii_case("connection") {
            saw_connection = true;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    if !saw_connection {
        if upgrade {
            head.push_str("Connection: Upgrade\r\n");
        } else {
            head.push_str("Connection: close\r\n");
        }
    }
    head.push_str("\r\n");
    head
}

fn request_path(dest: &str) -> String {
    path_and_query(dest)
}

pub(crate) fn header_value<'a>(request: &'a cqstream::ConnectRequest, name: &str) -> Option<&'a str> {
    let prefix = format!("{HTTP_HEADER_KEY}:");
    request.metadata.iter().find_map(|(key, value)| {
        key.strip_prefix(&prefix)
            .filter(|header| header.eq_ignore_ascii_case(name))
            .map(|_| value.as_str())
    })
}

fn content_length(request: &cqstream::ConnectRequest) -> Option<u64> {
    header_value(request, "content-length").and_then(|v| v.parse().ok())
}

fn is_chunked(request: &cqstream::ConnectRequest) -> bool {
    header_value(request, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
}

fn is_upgrade(request: &cqstream::ConnectRequest) -> bool {
    header_value(request, "upgrade").is_some()
        || header_value(request, "connection")
            .map(|v| v.to_ascii_lowercase().contains("upgrade"))
            .unwrap_or(false)
}

/// The edge marks an upgrade by connection type, and may not keep the
/// `Upgrade`/`Connection` headers in the metadata, so check both.
fn is_websocket(request: &cqstream::ConnectRequest) -> bool {
    request.conn_type == cqstream::ConnectionType::Websocket || is_upgrade(request)
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

// ── Response head ───────────────────────────────────────────────────────────

async fn read_response_head<R>(io: &mut R) -> Result<(u16, Vec<(String, String)>, Vec<u8>)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];
    loop {
        let n = tokio::io::AsyncReadExt::read(io, &mut tmp).await?;
        if n == 0 {
            bail!("origin closed before sending a response head");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_HEAD_BYTES {
            bail!("origin response head exceeds {MAX_HEAD_BYTES} bytes");
        }
        let parsed = {
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut response = httparse::Response::new(&mut headers);
            match response.parse(&buf)? {
                httparse::Status::Complete(consumed) => {
                    let status = response.code.ok_or_else(|| anyhow!("no status code"))?;
                    let pairs = response
                        .headers
                        .iter()
                        .map(|h| {
                            (
                                h.name.to_string(),
                                String::from_utf8_lossy(h.value).into_owned(),
                            )
                        })
                        .collect::<Vec<_>>();
                    Some((status, pairs, consumed))
                }
                httparse::Status::Partial => None,
            }
        };
        if let Some((status, pairs, consumed)) = parsed {
            let leftover = buf.split_off(consumed);
            return Ok((status, pairs, leftover));
        }
    }
}

fn headers_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

// ── Byte pumps ──────────────────────────────────────────────────────────────

async fn copy_futures_to_tokio_n<R, W>(
    src: &mut R,
    dst: &mut W,
    mut remaining: u64,
    metrics: &Metrics,
) -> Result<()>
where
    R: futures::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let n = futures::io::AsyncReadExt::read(src, &mut buf[..want]).await?;
        if n == 0 {
            bail!("edge EOF with {remaining} request bytes still expected");
        }
        tokio::io::AsyncWriteExt::write_all(dst, &buf[..n]).await?;
        metrics.add_in(n as u64);
        remaining -= n as u64;
    }
    Ok(())
}

async fn copy_futures_to_tokio_eof<R, W>(
    src: &mut R,
    dst: &mut W,
    metrics: &Metrics,
) -> Result<u64>
where
    R: futures::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = futures::io::AsyncReadExt::read(src, &mut buf).await?;
        if n == 0 {
            break;
        }
        tokio::io::AsyncWriteExt::write_all(dst, &buf[..n]).await?;
        metrics.add_in(n as u64);
        total += n as u64;
    }
    Ok(total)
}

async fn copy_tokio_to_futures_n<R, W>(
    src: &mut R,
    dst: &mut W,
    mut remaining: u64,
    metrics: &Metrics,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: futures::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let n = tokio::io::AsyncReadExt::read(src, &mut buf[..want]).await?;
        if n == 0 {
            bail!("origin EOF with {remaining} response bytes still expected");
        }
        futures::io::AsyncWriteExt::write_all(dst, &buf[..n]).await?;
        metrics.add_out(n as u64);
        remaining -= n as u64;
    }
    Ok(())
}

async fn copy_tokio_to_futures_eof<R, W>(
    src: &mut R,
    dst: &mut W,
    metrics: &Metrics,
) -> Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: futures::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = tokio::io::AsyncReadExt::read(src, &mut buf).await?;
        if n == 0 {
            break;
        }
        futures::io::AsyncWriteExt::write_all(dst, &buf[..n]).await?;
        metrics.add_out(n as u64);
        total += n as u64;
    }
    Ok(total)
}

async fn futures_write_all<W>(dst: &mut W, bytes: &[u8]) -> Result<()>
where
    W: futures::io::AsyncWrite + Unpin,
{
    futures::io::AsyncWriteExt::write_all(dst, bytes).await?;
    Ok(())
}

async fn futures_close<W>(dst: &mut W) -> Result<()>
where
    W: futures::io::AsyncWrite + Unpin,
{
    futures::io::AsyncWriteExt::close(dst).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloudflare_quick_tunnel::stream::ConnectionType;

    fn req(dest: &str, metadata: Vec<(&str, &str)>) -> cqstream::ConnectRequest {
        cqstream::ConnectRequest {
            dest: dest.to_string(),
            conn_type: ConnectionType::Http,
            metadata: metadata
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn head_and_flags() {
        let request = req(
            "https://x/a",
            vec![
                (HTTP_METHOD_KEY, "POST"),
                (HTTP_HOST_KEY, "x"),
                ("HttpHeader:Content-Length", "5"),
            ],
        );
        assert_eq!(content_length(&request), Some(5));
        let head = build_request_head(&request, &OriginOptions::default(), false);
        assert!(head.starts_with("POST /a HTTP/1.1\r\n"));
        assert!(head.contains("Connection: close\r\n"));
    }

    #[test]
    fn upgrade_and_chunked() {
        let ws = req("https://x/ws", vec![("HttpHeader:Upgrade", "websocket")]);
        assert!(is_upgrade(&ws));
        let chunked = req(
            "https://x/u",
            vec![("HttpHeader:Transfer-Encoding", "chunked")],
        );
        assert!(is_chunked(&chunked));
    }

    #[test]
    fn form_parsing() {
        let fields = parse_form(b"password=123456&next=%2Fs%2Fabc%2F&x=a+b");
        assert!(fields.contains(&("password".to_string(), "123456".to_string())));
        assert!(fields.contains(&("next".to_string(), "/s/abc/".to_string())));
        assert!(fields.contains(&("x".to_string(), "a b".to_string())));
    }

    #[test]
    fn strips_accept_encoding_on_request() {
        let request = req("https://x/", vec![("HttpHeader:Accept-Encoding", "gzip, br")]);
        let head = build_request_head(&request, &OriginOptions::default(), false);
        assert!(head.contains("Accept-Encoding: gzip, br"));

        let options = OriginOptions {
            strip_accept_encoding: true,
            ..OriginOptions::default()
        };
        let head = build_request_head(&request, &options, false);
        assert!(!head.to_ascii_lowercase().contains("accept-encoding"));
    }

    #[test]
    fn response_meta_prefixes_headers() {
        let headers = vec![
            ("Content-Type".to_string(), "text/plain".to_string()),
            ("Set-Cookie".to_string(), "a=b".to_string()),
            ("HttpHeader:Location".to_string(), "/next".to_string()),
        ];
        let meta = response_meta_pairs(303, &headers);
        assert_eq!(meta[0], ("HttpStatus".to_string(), "303".to_string()));
        assert!(meta.contains(&("HttpHeader:Content-Type".to_string(), "text/plain".to_string())));
        assert!(meta.contains(&("HttpHeader:Set-Cookie".to_string(), "a=b".to_string())));
        assert!(meta.contains(&("HttpHeader:Location".to_string(), "/next".to_string())));
        assert!(!meta.iter().any(|(k, _)| k == "Content-Type"));
    }
}
