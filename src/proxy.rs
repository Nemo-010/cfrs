//! Proxy one inbound tunnel stream to the local origin.
//!
//! The edge opens a bidi QUIC stream per request and frames it as
//! `[6-byte signature][2-byte version][capnp ConnectRequest]`. We answer with
//! the matching `ConnectResponse` (status + headers in its metadata) and then
//! the stream carries the body. This is the same framing `cloudflared` uses;
//! the `cloudflare-quick-tunnel` crate supplies the codec and we supply the
//! unix-socket dial.
//!
//! Plain requests (bounded `Content-Length`, no Upgrade) take a sequential
//! path: forward exactly the request body, read the response head, forward it,
//! then forward exactly the response body. Chunked requests and WebSocket
//! upgrades take a bidirectional pump instead.

use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use cloudflare_quick_tunnel::stream as cqstream;
use cloudflare_quick_tunnel::stream::{HTTP_HEADER_KEY, HTTP_HOST_KEY, HTTP_METHOD_KEY};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::origin::{Origin, OriginStream};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEAD_BYTES: usize = 32 * 1024;

pub async fn serve_stream(origin: Origin, send: quinn::SendStream, recv: quinn::RecvStream) {
    if let Err(err) = serve_inner(origin, send, recv).await {
        tracing::warn!(error = %err, "stream proxy failed");
    }
}

async fn serve_inner(
    origin: Origin,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
) -> Result<()> {
    let (mut edge_r, mut edge_w) = cqstream::split(send, recv);
    let request = cqstream::read_connect_request(&mut edge_r).await?;
    tracing::debug!(dest = %request.dest, kind = ?request.conn_type, "inbound stream");

    let mut origin_stream = tokio::time::timeout(CONNECT_TIMEOUT, origin.connect())
        .await
        .map_err(|_| anyhow!("origin connect timed out"))??;

    let upgrade = is_upgrade(&request);
    let head = build_request_head(&request, upgrade);
    origin_stream.write_all(head.as_bytes()).await?;

    if upgrade || is_chunked(&request) {
        return proxy_bidi(&mut edge_r, &mut edge_w, origin_stream).await;
    }

    // Bounded request body: forward exactly Content-Length bytes (or none).
    if let Some(len) = header_value(&request, "content-length").and_then(|v| v.parse::<u64>().ok())
    {
        if len > 0 {
            copy_futures_to_tokio_n(&mut edge_r, &mut origin_stream, len).await?;
        }
    }

    let (status, headers, leftover) = read_response_head(&mut origin_stream).await?;
    write_response_meta(&mut edge_w, status, &headers).await?;
    if !leftover.is_empty() {
        futures_write_all(&mut edge_w, &leftover).await?;
    }

    let resp_len = headers_value(&headers, "content-length").and_then(|v| v.parse::<u64>().ok());
    match resp_len {
        Some(total) => {
            let remaining = total.saturating_sub(leftover.len() as u64);
            if remaining > 0 {
                copy_tokio_to_futures_n(&mut origin_stream, &mut edge_w, remaining).await?;
            }
        }
        None => {
            // We asked the origin to close, so EOF marks the body end.
            copy_tokio_to_futures_eof(&mut origin_stream, &mut edge_w).await?;
        }
    }
    futures_close(&mut edge_w).await?;
    Ok(())
}

async fn proxy_bidi<R, W>(edge_r: &mut R, edge_w: &mut W, origin_stream: OriginStream) -> Result<()>
where
    R: futures::io::AsyncRead + Unpin,
    W: futures::io::AsyncWrite + Unpin,
{
    let (mut origin_r, mut origin_w) = tokio::io::split(origin_stream);

    let request_pump = async {
        let _ = copy_futures_to_tokio_eof(edge_r, &mut origin_w).await;
        let _ = origin_w.shutdown().await;
    };
    let response_pump = async {
        let (status, headers, leftover) = read_response_head(&mut origin_r).await?;
        write_response_meta(edge_w, status, &headers).await?;
        if !leftover.is_empty() {
            futures_write_all(edge_w, &leftover).await?;
        }
        copy_tokio_to_futures_eof(&mut origin_r, edge_w).await?;
        futures_close(edge_w).await?;
        Ok::<(), anyhow::Error>(())
    };

    let (_, response) = tokio::join!(request_pump, response_pump);
    response
}

// ── Request head ────────────────────────────────────────────────────────────

fn build_request_head(req: &cqstream::ConnectRequest, upgrade: bool) -> String {
    let method = req.meta(HTTP_METHOD_KEY).unwrap_or("GET");
    let host = req.meta(HTTP_HOST_KEY).unwrap_or("");
    let path = request_path(&req.dest);
    let header_prefix = format!("{HTTP_HEADER_KEY}:");

    let mut head = String::with_capacity(256);
    head.push_str(method);
    head.push(' ');
    head.push_str(&path);
    head.push_str(" HTTP/1.1\r\n");
    if !host.is_empty() {
        head.push_str("Host: ");
        head.push_str(host);
        head.push_str("\r\n");
    }

    let mut saw_connection = false;
    for (key, value) in &req.metadata {
        let Some(name) = key.strip_prefix(&header_prefix) else {
            continue;
        };
        if name.eq_ignore_ascii_case("host") {
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
    if let Some(scheme) = dest.find("://") {
        let rest = &dest[scheme + 3..];
        return match rest.find('/') {
            Some(slash) => rest[slash..].to_string(),
            None => "/".to_string(),
        };
    }
    if dest.starts_with('/') {
        dest.to_string()
    } else {
        "/".to_string()
    }
}

fn header_value<'a>(req: &'a cqstream::ConnectRequest, name: &str) -> Option<&'a str> {
    let prefix = format!("{HTTP_HEADER_KEY}:");
    req.metadata.iter().find_map(|(key, value)| {
        key.strip_prefix(&prefix)
            .filter(|header| header.eq_ignore_ascii_case(name))
            .map(|_| value.as_str())
    })
}

fn is_chunked(req: &cqstream::ConnectRequest) -> bool {
    header_value(req, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
}

fn is_upgrade(req: &cqstream::ConnectRequest) -> bool {
    header_value(req, "upgrade").is_some()
        || header_value(req, "connection")
            .map(|v| v.to_ascii_lowercase().contains("upgrade"))
            .unwrap_or(false)
}

// ── Response head ───────────────────────────────────────────────────────────

async fn write_response_meta<W>(
    writer: &mut W,
    status: u16,
    headers: &[(String, String)],
) -> Result<()>
where
    W: futures::io::AsyncWrite + Unpin,
{
    let mut meta: Vec<(String, String)> = Vec::with_capacity(headers.len() + 1);
    meta.push((cqstream::HTTP_STATUS_KEY.to_string(), status.to_string()));
    for (name, value) in headers {
        meta.push((format!("{HTTP_HEADER_KEY}:{name}"), value.clone()));
    }
    let refs: Vec<(&str, &str)> = meta.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    cqstream::write_connect_response(writer, "", &refs).await?;
    Ok(())
}

async fn read_response_head<R>(origin: &mut R) -> Result<(u16, Vec<(String, String)>, Vec<u8>)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];
    loop {
        let n = origin.read(&mut tmp).await?;
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
//
// Written against fully-qualified trait methods so the futures-io and tokio-io
// extension traits never collide.

async fn copy_futures_to_tokio_n<R, W>(src: &mut R, dst: &mut W, mut remaining: u64) -> Result<()>
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
        remaining -= n as u64;
    }
    Ok(())
}

async fn copy_futures_to_tokio_eof<R, W>(src: &mut R, dst: &mut W) -> Result<u64>
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
        total += n as u64;
    }
    Ok(total)
}

async fn copy_tokio_to_futures_n<R, W>(src: &mut R, dst: &mut W, mut remaining: u64) -> Result<()>
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
        remaining -= n as u64;
    }
    Ok(())
}

async fn copy_tokio_to_futures_eof<R, W>(src: &mut R, dst: &mut W) -> Result<u64>
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
    fn path_is_extracted() {
        assert_eq!(request_path("https://x.trycloudflare.com/a?b=1"), "/a?b=1");
        assert_eq!(request_path("https://x.trycloudflare.com"), "/");
        assert_eq!(request_path("/relative"), "/relative");
    }

    #[test]
    fn head_has_method_host_and_headers() {
        let request = req(
            "https://x/a",
            vec![
                (HTTP_METHOD_KEY, "POST"),
                (HTTP_HOST_KEY, "x"),
                ("HttpHeader:X-Test", "1"),
            ],
        );
        let head = build_request_head(&request, false);
        assert!(head.starts_with("POST /a HTTP/1.1\r\n"));
        assert!(head.contains("Host: x\r\n"));
        assert!(head.contains("X-Test: 1\r\n"));
        assert!(head.contains("Connection: close\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
    }

    #[test]
    fn upgrade_is_detected() {
        let request = req("https://x/ws", vec![("HttpHeader:Upgrade", "websocket")]);
        assert!(is_upgrade(&request));
        let head = build_request_head(&request, true);
        assert!(head.contains("Upgrade: websocket\r\n"));
        assert!(head.contains("Connection: Upgrade\r\n"));
    }

    #[test]
    fn chunked_is_detected() {
        let request = req(
            "https://x/upload",
            vec![("HttpHeader:Transfer-Encoding", "chunked")],
        );
        assert!(is_chunked(&request));
    }
}
