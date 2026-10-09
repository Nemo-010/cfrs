//! Local origin: where inbound tunnel streams are delivered.
//!
//! A sealed sandbox refuses `bind(2)` on `AF_INET` but allows `AF_UNIX`, so the
//! origin may be a filesystem socket. `Origin::Tcp` exists for normal hosts.
//! The built-in demo origin is an HTTP/1.1 server on a unix socket that echoes
//! a random token, which makes the end-to-end proof checkable.

use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UnixListener, UnixStream};

/// Where cfrs should deliver requests.
#[derive(Debug, Clone)]
pub enum Origin {
    Unix(PathBuf),
    Tcp(String),
}

impl Origin {
    pub fn describe(&self) -> String {
        match self {
            Origin::Unix(path) => format!("unix:{}", path.display()),
            Origin::Tcp(addr) => format!("tcp://{addr}"),
        }
    }

    pub async fn connect(&self) -> std::io::Result<OriginStream> {
        match self {
            Origin::Unix(path) => UnixStream::connect(path).await.map(OriginStream::Unix),
            Origin::Tcp(addr) => TcpStream::connect(addr).await.map(OriginStream::Tcp),
        }
    }
}

/// Either flavour of origin connection, so the proxy can be written once.
pub enum OriginStream {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl AsyncRead for OriginStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            OriginStream::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
            OriginStream::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for OriginStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            OriginStream::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
            OriginStream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            OriginStream::Unix(stream) => Pin::new(stream).poll_flush(cx),
            OriginStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            OriginStream::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
            OriginStream::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// A random proof token. UUID v4 is already a dependency, so no RNG crate is
/// pulled in just for this.
pub fn random_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// Serve a tiny HTTP/1.1 origin on `path` for the lifetime of the process.
pub async fn serve_demo(path: PathBuf, token: String) -> std::io::Result<()> {
    // A bound unix socket inode outlives the process that made it.
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    tracing::info!(path = %path.display(), "demo origin listening");
    loop {
        let (stream, _) = listener.accept().await?;
        let token = token.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_demo(stream, &token).await {
                tracing::debug!(error = %err, "demo request ended");
            }
        });
    }
}

async fn handle_demo(mut stream: UnixStream, token: &str) -> std::io::Result<()> {
    const MAX_HEAD: usize = 64 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];

    let (method, path) = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_HEAD {
            return Ok(());
        }
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(_)) => {
                break (
                    req.method.unwrap_or("GET").to_string(),
                    req.path.unwrap_or("/").to_string(),
                );
            }
            Ok(httparse::Status::Partial) => {}
            Err(_) => return Ok(()),
        }
    };

    let body = format!("cfrs demo origin\ntoken: {token}\nmethod: {method}\npath: {path}\n");
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}
