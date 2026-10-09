//! Upload / download / proxy sessions — the feature set quickbridge brings,
//! reimplemented as a library service so a tunnel can expose it directly.
//!
//! - **Upload**: a multipart form saves files into a directory.
//! - **Download**: serves one file (or a clipboard snapshot) once.
//! - **Proxy**: forwards everything to an existing local HTTP port.
//!
//! A random token lives in the URL path; an optional 6-digit PIN gate adds a
//! second factor. `stop_after` tears the session down after the first
//! successful transfer.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use serde::Deserialize;
use tokio::sync::Notify;

use crate::gate::{Gate, UNLOCK_PATH};
use crate::util::{ensure_dir, human_bytes, sanitize_filename};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareMode {
    Upload,
    Download,
    Proxy,
}

impl ShareMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "upload" => Ok(ShareMode::Upload),
            "download" => Ok(ShareMode::Download),
            "proxy" => Ok(ShareMode::Proxy),
            other => bail!("unknown share mode {other:?}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ShareMode::Upload => "upload",
            ShareMode::Download => "download",
            ShareMode::Proxy => "proxy",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ShareConfig {
    pub mode: ShareMode,
    pub token: String,
    pub dest: PathBuf,
    pub file: Option<PathBuf>,
    pub target: Option<String>,
    pub max_bytes: u64,
    pub max_files: u32,
    pub stop_after: bool,
    pub gate: Gate,
}

impl ShareConfig {
    pub fn upload(dest: impl Into<PathBuf>) -> Self {
        Self {
            mode: ShareMode::Upload,
            token: crate::util::random_token(),
            dest: dest.into(),
            file: None,
            target: None,
            max_bytes: 512 * 1024 * 1024,
            max_files: 32,
            stop_after: false,
            gate: Gate::off(),
        }
    }

    pub fn download(file: impl Into<PathBuf>) -> Self {
        Self {
            mode: ShareMode::Download,
            token: crate::util::random_token(),
            dest: PathBuf::new(),
            file: Some(file.into()),
            target: None,
            max_bytes: 2 * 1024 * 1024 * 1024,
            max_files: 1,
            stop_after: false,
            gate: Gate::off(),
        }
    }

    pub fn proxy(target: impl Into<String>) -> Self {
        Self {
            mode: ShareMode::Proxy,
            token: crate::util::random_token(),
            dest: PathBuf::new(),
            file: None,
            target: Some(target.into()),
            max_bytes: 32 * 1024 * 1024,
            max_files: 1,
            stop_after: false,
            gate: Gate::pin(),
        }
    }

    pub fn with_gate(mut self, gate: Gate) -> Self {
        self.gate = gate;
        self
    }

    pub fn stop_after(mut self, yes: bool) -> Self {
        self.stop_after = yes;
        self
    }

    pub fn describe(&self) -> String {
        match self.mode {
            ShareMode::Upload => format!("share:upload:{}", self.dest.display()),
            ShareMode::Download => format!(
                "share:download:{}",
                self.file.as_ref().map(|p| p.display().to_string()).unwrap_or_default()
            ),
            ShareMode::Proxy => format!("share:proxy:{}", self.target.clone().unwrap_or_default()),
        }
    }

    /// Path appended to the public URL for the session.
    pub fn url_path(&self) -> String {
        match self.mode {
            ShareMode::Proxy => "/".to_string(),
            _ => format!("/s/{}/", self.token),
        }
    }
}

/// Cross-task session control: last activity + stop signal.
pub struct ShareControl {
    last: Mutex<Instant>,
    stop: Notify,
}

impl Default for ShareControl {
    fn default() -> Self {
        Self {
            last: Mutex::new(Instant::now()),
            stop: Notify::new(),
        }
    }
}

impl ShareControl {
    pub fn touch(&self) {
        if let Ok(mut guard) = self.last.lock() {
            *guard = Instant::now();
        }
    }

    pub fn idle_for(&self) -> Duration {
        self.last
            .lock()
            .map(|guard| guard.elapsed())
            .unwrap_or_default()
    }

    pub fn request_stop(&self) {
        self.stop.notify_waiters();
    }

    pub async fn wait_stop(&self) {
        self.stop.notified().await;
    }
}

struct UploadState {
    dest: PathBuf,
    token: String,
    max_bytes: u64,
    max_files: u32,
    used_files: AtomicU32,
    used_bytes: AtomicU64,
    stop_after: bool,
    gate: Gate,
    control: Arc<ShareControl>,
}

struct DownloadState {
    token: String,
    file: PathBuf,
    name: String,
    stop_after: bool,
    gate: Gate,
    control: Arc<ShareControl>,
}

/// A built share session.
pub struct ShareApp {
    config: ShareConfig,
    control: Arc<ShareControl>,
    router: Router,
}

impl ShareApp {
    pub fn new(config: ShareConfig) -> Result<Self> {
        if config.mode == ShareMode::Proxy {
            bail!("proxy sessions are forwarded by the tunnel, not served by ShareApp");
        }
        if config.mode == ShareMode::Upload {
            ensure_dir(&config.dest)?;
        }
        if let Some(file) = &config.file {
            if !file.is_file() {
                bail!("file to share does not exist: {}", file.display());
            }
        }
        let control = Arc::new(ShareControl::default());
        let router = match config.mode {
            ShareMode::Upload => upload_router(&config, control.clone()),
            ShareMode::Download => download_router(&config, control.clone())?,
            ShareMode::Proxy => unreachable!(),
        };
        Ok(Self {
            config,
            control,
            router,
        })
    }

    pub fn config(&self) -> &ShareConfig {
        &self.config
    }

    pub fn control(&self) -> Arc<ShareControl> {
        self.control.clone()
    }

    pub fn router(&self) -> Router {
        self.router.clone()
    }
}

// ── Upload ──────────────────────────────────────────────────────────────────

fn upload_router(config: &ShareConfig, control: Arc<ShareControl>) -> Router {
    let state = Arc::new(UploadState {
        dest: config.dest.clone(),
        token: config.token.clone(),
        max_bytes: config.max_bytes,
        max_files: config.max_files,
        used_files: AtomicU32::new(0),
        used_bytes: AtomicU64::new(0),
        stop_after: config.stop_after,
        gate: config.gate.clone(),
        control,
    });
    let limit = (config.max_bytes as usize).saturating_add(1024 * 1024);
    Router::new()
        .route(UNLOCK_PATH, post(unlock_upload))
        .route("/", get(|| async { Redirect::to("/s/") }))
        .route("/s/{token}", get(upload_landing))
        .route("/s/{token}/", get(upload_landing))
        .route("/s/{token}/upload", post(upload_receive))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

#[derive(Deserialize)]
struct UnlockForm {
    password: String,
    #[serde(default)]
    next: String,
}

async fn unlock_upload(
    State(state): State<Arc<UploadState>>,
    Form(form): Form<UnlockForm>,
) -> Response {
    unlock_response(&state.gate, &form.password, &form.next)
}

fn unlock_response(gate: &Gate, password: &str, next: &str) -> Response {
    match gate.unlock(password) {
        Some(cookie) => {
            let next = if next.starts_with('/') { next } else { "/" };
            let mut response = Redirect::to(next).into_response();
            if let Ok(value) = header::HeaderValue::from_str(&cookie) {
                response.headers_mut().insert(header::SET_COOKIE, value);
            }
            response
        }
        None => Html(gate.page_html(next, true)).into_response(),
    }
}

fn gate_blocked(gate: &Gate, headers: &HeaderMap, uri: &Uri) -> Option<Response> {
    if uri.path() == UNLOCK_PATH || gate.is_open(headers) {
        return None;
    }
    let next = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    Some(Html(gate.page_html(next, false)).into_response())
}

async fn upload_landing(
    State(state): State<Arc<UploadState>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    if let Some(response) = gate_blocked(&state.gate, &headers, &uri) {
        return response;
    }
    state.control.touch();
    Html(upload_page(&state.token, state.max_bytes)).into_response()
}

async fn upload_receive(
    State(state): State<Arc<UploadState>>,
    headers: HeaderMap,
    uri: Uri,
    mut multipart: Multipart,
) -> Response {
    if let Some(response) = gate_blocked(&state.gate, &headers, &uri) {
        return response;
    }
    state.control.touch();

    let mut saved = Vec::new();
    let mut total = 0u64;
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(err) => {
                return (StatusCode::BAD_REQUEST, format!("bad multipart body: {err}")).into_response()
            }
        };
        let Some(original) = field.file_name().map(str::to_string) else {
            continue;
        };
        let name = sanitize_filename(&original);
        if state.used_files.load(Ordering::Relaxed) >= state.max_files {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("session file limit reached ({} files)", state.max_files),
            )
                .into_response();
        }

        let path = unique_path(&state.dest, &name);
        let mut file = match tokio::fs::File::create(&path).await {
            Ok(file) => file,
            Err(err) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("cannot create file: {err}"))
                    .into_response()
            }
        };
        let mut field = field;
        let mut written = 0u64;
        loop {
            match field.chunk().await {
                Ok(Some(chunk)) => {
                    written += chunk.len() as u64;
                    if written > state.max_bytes {
                        let _ = tokio::fs::remove_file(&path).await;
                        return (
                            StatusCode::PAYLOAD_TOO_LARGE,
                            format!("file exceeds {}", human_bytes(state.max_bytes)),
                        )
                            .into_response();
                    }
                    if let Err(err) = tokio::io::AsyncWriteExt::write_all(&mut file, &chunk).await {
                        let _ = tokio::fs::remove_file(&path).await;
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("write failed: {err}"),
                        )
                            .into_response();
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    let _ = tokio::fs::remove_file(&path).await;
                    return (StatusCode::BAD_REQUEST, format!("upload aborted: {err}")).into_response();
                }
            }
        }
        let _ = tokio::io::AsyncWriteExt::flush(&mut file).await;
        state.used_files.fetch_add(1, Ordering::Relaxed);
        state.used_bytes.fetch_add(written, Ordering::Relaxed);
        total += written;
        saved.push((name, written));
    }

    if saved.is_empty() {
        return (StatusCode::BAD_REQUEST, "no files in upload").into_response();
    }
    if state.stop_after {
        state.control.request_stop();
    }
    let list: String = saved
        .iter()
        .map(|(name, size)| format!("<li>{} — {}</li>", html_escape(name), human_bytes(*size)))
        .collect();
    Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>cfrs — uploaded</title></head><body>\
         <h1>Received {} file(s), {}</h1><ul>{list}</ul></body></html>",
        saved.len(),
        human_bytes(total)
    ))
    .into_response()
}

fn upload_page(token: &str, max_bytes: u64) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>cfrs — upload</title><style>\
         body{{font-family:system-ui,sans-serif;background:#0b1020;color:#e8ecf5;\
         display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}\
         main{{background:#161d33;padding:2rem;border-radius:12px;width:min(90vw,420px)}}\
         button{{margin-top:1rem;width:100%;padding:.8rem;border:0;border-radius:8px;\
         background:#4f7cff;color:#fff;font-size:1rem}}input[type=file]{{width:100%}}\
         p{{color:#9aa7c7;font-size:.9rem}}</style></head><body><main>\
         <h1>Send files</h1><p>Max {} per file.</p>\
         <form method=\"post\" action=\"/s/{token}/upload\" enctype=\"multipart/form-data\">\
         <input type=\"file\" name=\"files\" multiple required>\
         <button type=\"submit\">Upload</button></form></main></body></html>",
        human_bytes(max_bytes)
    )
}

// ── Download ────────────────────────────────────────────────────────────────

fn download_router(config: &ShareConfig, control: Arc<ShareControl>) -> Result<Router> {
    let file = config
        .file
        .clone()
        .context("download session needs a file")?;
    let name = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".into());
    let state = Arc::new(DownloadState {
        token: config.token.clone(),
        file,
        name,
        stop_after: config.stop_after,
        gate: config.gate.clone(),
        control,
    });
    Ok(Router::new()
        .route(UNLOCK_PATH, post(unlock_download))
        .route("/s/{token}", get(download_landing))
        .route("/s/{token}/", get(download_landing))
        .route("/s/{token}/file", get(download_file))
        .with_state(state))
}

async fn unlock_download(
    State(state): State<Arc<DownloadState>>,
    Form(form): Form<UnlockForm>,
) -> Response {
    unlock_response(&state.gate, &form.password, &form.next)
}

async fn download_landing(
    State(state): State<Arc<DownloadState>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    if let Some(response) = gate_blocked(&state.gate, &headers, &uri) {
        return response;
    }
    state.control.touch();
    Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>cfrs — download</title></head><body>\
         <h1>{}</h1><p><a href=\"/s/{}/file\">Download</a></p></body></html>",
        html_escape(&state.name),
        state.token
    ))
    .into_response()
}

async fn download_file(
    State(state): State<Arc<DownloadState>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    if let Some(response) = gate_blocked(&state.gate, &headers, &uri) {
        return response;
    }
    state.control.touch();
    let file = match tokio::fs::File::open(&state.file).await {
        Ok(file) => file,
        Err(err) => {
            return (StatusCode::NOT_FOUND, format!("cannot open file: {err}")).into_response()
        }
    };
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    if state.stop_after {
        state.control.request_stop();
    }
    let disposition = format!(
        "attachment; filename=\"{}\"",
        state.name.replace('"', "")
    );
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(file));
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, len)
        .header(header::CONTENT_DISPOSITION, disposition)
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// ── helpers ─────────────────────────────────────────────────────────────────

fn unique_path(dir: &std::path::Path, name: &str) -> PathBuf {
    let mut candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) => (stem, format!(".{ext}")),
        None => (name, String::new()),
    };
    for index in 1..10_000 {
        candidate = dir.join(format!("{stem}-{index}{ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    candidate
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_names() {
        let dir = std::env::temp_dir().join(format!("cfrs-test-{}", crate::util::random_token()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        let second = unique_path(&dir, "a.txt");
        assert_ne!(second.file_name().unwrap(), "a.txt");
        assert!(second.to_string_lossy().ends_with("a-1.txt"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn proxy_path_is_root() {
        let config = ShareConfig::proxy("127.0.0.1:9000");
        assert_eq!(config.url_path(), "/");
        assert!(config.gate.enabled());
    }
}
