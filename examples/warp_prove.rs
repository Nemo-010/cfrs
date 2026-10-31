//! A proof of the WARP/MASQUE path that cannot pass by accident.
//!
//! Three kinds of measurement, in the order that makes them meaningful:
//!
//! 1. **Controls.** A connect to a port nothing listens on and a connect to an
//!    address that is not routable must both fail. If either "succeeds", the
//!    stack is reporting optimism rather than the network and every later line
//!    is worthless.
//! 2. **A real payload.** A DNS query for `example.com` is built by hand, sent
//!    through the tunnel to `1.1.1.1:53`, and the answer is parsed back out. A
//!    reply with an A record proves bytes crossed in both directions.
//! 3. **The destination the host refuses.** A TCP connection to the Cloudflare
//!    tunnel edge on port 7844, which this host cannot dial directly.
//!
//! ```sh
//! cargo run --example warp_prove
//! ```

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use cfrs::warp::WarpClient;

/// Build a minimal DNS query: one question, `A`, `IN`.
fn dns_query(name: &str, id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    out.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    out
}

/// Read a DNS name at `pos`, returning the position after it.
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(pos + 2); // compression pointer
        }
        pos += 1 + len;
    }
}

/// Parse a DNS answer, returning `(rcode, A record addresses)`.
fn parse_answers(msg: &[u8], qdcount: u16, ancount: u16) -> Option<(u8, Vec<std::net::Ipv4Addr>)> {
    let rcode = msg.get(3)? & 0x0F;
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(msg, pos)?;
        pos += 4; // qtype + qclass
    }
    let mut addrs = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(msg, pos)?;
        let rtype = u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]);
        let rdlen = u16::from_be_bytes([*msg.get(pos + 8)?, *msg.get(pos + 9)?]) as usize;
        pos += 10;
        if rtype == 1 && rdlen == 4 {
            addrs.push(std::net::Ipv4Addr::new(
                msg[pos],
                msg[pos + 1],
                msg[pos + 2],
                msg[pos + 3],
            ));
        }
        pos += rdlen;
    }
    Some((rcode, addrs))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let t0 = Instant::now();
    println!("== registration (anonymous, no account) ==");
    let client = WarpClient::register().await?;
    let device = client.device();
    println!("   device   {}", device.id);
    println!("   tunnel   {}", device.tunnel_type);
    println!("   address  {:?}", client.local_address()?);
    println!("   front    {:?}", device.masque_endpoint());
    println!("   took     {:?}", t0.elapsed());

    println!("\n== MASQUE CONNECT-IP over TCP 443 ==");
    let t1 = Instant::now();
    let stack = client.connect().await?;
    println!("   up in {:?}", t1.elapsed());

    println!("\n== controls: these MUST fail ==");
    let mut controls_ok = true;
    // A closed port on a reachable host.
    match tokio::time::timeout(
        Duration::from_secs(8),
        stack.tcp_connect("1.1.1.1:9".parse()?),
    )
    .await
    {
        Ok(Ok(_)) => {
            controls_ok = false;
            println!("   BAD  closed port 1.1.1.1:9 reported connected");
        }
        Ok(Err(err)) => println!("   ok   closed port refused: {err}"),
        Err(_) => println!("   ok   closed port timed out (no SYN-ACK)"),
    }
    // An address that is not routable at all (TEST-NET-1).
    match tokio::time::timeout(
        Duration::from_secs(8),
        stack.tcp_connect("192.0.2.1:443".parse()?),
    )
    .await
    {
        Ok(Ok(_)) => {
            controls_ok = false;
            println!("   BAD  unroutable 192.0.2.1:443 reported connected");
        }
        Ok(Err(err)) => println!("   ok   unroutable address refused: {err}"),
        Err(_) => println!("   ok   unroutable address timed out"),
    }

    println!("\n== a real payload: DNS over the tunnel ==");
    let udp = stack.udp_bind().await?;
    let id: u16 = 0x4b1d;
    let query = dns_query("example.com", id);
    let dns: SocketAddr = "1.1.1.1:53".parse()?;
    udp.send_to(query.clone(), dns).await?;
    let (reply, from) = tokio::time::timeout(Duration::from_secs(8), udp.recv_from(4096))
        .await
        .context_wrap()??;
    let qdcount = u16::from_be_bytes([reply[4], reply[5]]);
    let ancount = u16::from_be_bytes([reply[6], reply[7]]);
    let echoed_id = u16::from_be_bytes([reply[0], reply[1]]);
    let (rcode, addrs) = parse_answers(&reply, qdcount, ancount).unwrap_or((255, Vec::new()));
    println!("   from     {from}");
    println!("   id match {}", echoed_id == id);
    println!("   rcode    {rcode}");
    println!("   answers  {addrs:?}");
    let dns_ok = echoed_id == id && rcode == 0 && !addrs.is_empty();

    println!("\n== the destination this host refuses: the tunnel edge on 7844 ==");
    let edge: SocketAddr = "198.41.192.27:7844".parse()?;
    let edge_ok = match tokio::time::timeout(Duration::from_secs(10), stack.tcp_connect(edge)).await
    {
        Ok(Ok(conn)) => {
            println!("   ok   {edge} connected from inside the tunnel");
            conn.close().await;
            true
        }
        Ok(Err(err)) => {
            println!("   FAIL {edge}: {err}");
            false
        }
        Err(_) => {
            println!("   FAIL {edge}: timed out");
            false
        }
    };

    println!("\n== verdict ==");
    println!(
        "   controls            {}",
        if controls_ok { "PASS" } else { "FAIL" }
    );
    println!(
        "   payload round trip  {}",
        if dns_ok { "PASS" } else { "FAIL" }
    );
    println!(
        "   edge on 7844        {}",
        if edge_ok { "PASS" } else { "FAIL" }
    );
    println!("   total               {:?}", t0.elapsed());

    if !(controls_ok && dns_ok && edge_ok) {
        std::process::exit(1);
    }
    Ok(())
}

/// Small helper so a timeout reads as an error rather than a panic.
trait ContextWrap<T> {
    fn context_wrap(self) -> anyhow::Result<T>;
}

impl<T> ContextWrap<T> for Result<T, tokio::time::error::Elapsed> {
    fn context_wrap(self) -> anyhow::Result<T> {
        self.map_err(|_| anyhow::anyhow!("timed out waiting for the DNS reply"))
    }
}
