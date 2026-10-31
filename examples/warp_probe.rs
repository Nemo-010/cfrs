//! Live probe for the WARP/MASQUE path.
//!
//! Registers anonymously, opens a MASQUE CONNECT-IP tunnel over TCP 443, then
//! tries to reach destinations through it — including the Cloudflare tunnel edge
//! on port 7844, which the host itself refuses.
//!
//! ```sh
//! cargo run --example warp_probe
//! ```

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use cfrs::warp::WarpClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let t0 = Instant::now();
    println!("== 1. anonymous registration ==");
    let client = WarpClient::register().await?;
    let device = client.device();
    println!("   device   {}", device.id);
    println!("   account  {}", device.account.id);
    println!("   tunnel   {}", device.tunnel_type);
    println!("   ipv4     {:?}", device.ipv4());
    println!("   ipv6     {:?}", device.ipv6());
    println!("   edge     {:?}", device.masque_endpoint());
    println!("   took     {:?}", t0.elapsed());

    println!("== 2. MASQUE CONNECT-IP over TCP 443 ==");
    let t1 = Instant::now();
    let stack = client.connect().await?;
    println!("   tunnel up in {:?}", t1.elapsed());

    let targets: Vec<(&str, SocketAddr)> = vec![
        ("cloudflare-tunnel-edge", "198.41.192.27:7844".parse().unwrap()),
        ("cloudflare-dns", "1.1.1.1:443".parse().unwrap()),
        ("example-http", "93.184.215.14:80".parse().unwrap()),
    ];

    println!("== 3. TCP through the tunnel ==");
    for (name, addr) in targets {
        let t = Instant::now();
        match tokio::time::timeout(Duration::from_secs(12), stack.tcp_connect(addr)).await {
            Ok(Ok(conn)) => {
                println!("   OK   {name:<24} {addr} connected in {:?}", t.elapsed());
                conn.close().await;
            }
            Ok(Err(err)) => println!("   FAIL {name:<24} {addr} {err}"),
            Err(_) => println!("   TIMEOUT {name:<24} {addr}"),
        }
    }

    println!("== done in {:?} ==", t0.elapsed());
    Ok(())
}
