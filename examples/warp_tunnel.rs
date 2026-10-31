//! Live proof: a quick tunnel whose edge connection is carried by WARP.
//!
//! Starts a tiny HTTP origin, registers anonymously with WARP, opens the
//! MASQUE tunnel over TCP 443, then provisions a quick tunnel whose edge
//! connection is bridged through that tunnel — so port 7844 is never dialled
//! by the host — and fetches the public URL to confirm a real traversal.
//!
//! ```sh
//! cargo run --example warp_tunnel
//! ```

use std::time::{Duration, Instant};

use cfrs::warp::{start_quick_tunnel, WarpClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A minimal HTTP origin: answers every request with a marker that increments,
/// so two fetches prove two real traversals rather than one cached response.
async fn origin(listener: tokio::net::TcpListener) -> anyhow::Result<u16> {
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let mut marker = 0u64;
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            marker += 1;
            let body = format!("cfrs-warp-origin marker={marker}\n");
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    Ok(port)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let t0 = Instant::now();

    println!("== 1. local origin ==");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binding a local origin");
    let port = origin(listener).await?;
    println!("   origin   http://127.0.0.1:{port}");

    println!("== 2. WARP registration + MASQUE over TCP 443 ==");
    let client = WarpClient::register().await?;
    println!("   edge     {:?}", client.device().masque_endpoint());
    let stack = client.connect().await?;
    println!("   tunnel up");

    println!("== 3. quick tunnel carried by WARP ==");
    let tunnel = start_quick_tunnel(stack, port).await?;
    println!("   url      {}", tunnel.url);
    println!("   edge     {} (bridged, never dialled by the host)", tunnel.edge);
    println!("   colo     {}", tunnel.location);

    println!("== 4. fetch the public URL ==");
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    for attempt in 1..=4 {
        let t = Instant::now();
        match http.get(&tunnel.url).send().await {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                println!(
                    "   attempt {attempt}: HTTP {status} in {:?} -> {}",
                    t.elapsed(),
                    body.trim()
                );
                if status.is_success() && body.contains("marker=") {
                    println!("== PROOF: the public URL served the origin through WARP ==");
                    println!("   total {:?}", t0.elapsed());
                    tunnel.shutdown().await;
                    return Ok(());
                }
            }
            Err(err) => println!("   attempt {attempt}: {err}"),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    println!("== no successful fetch; edge may still be propagating ==");
    tunnel.shutdown().await;
    Ok(())
}
