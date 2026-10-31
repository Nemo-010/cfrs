//! The library surface the README promises, compiled.
//!
//! The doc examples on `lib.rs`, `warp` and `warp::edge` are the three shapes a
//! caller actually writes, and `cargo test --doc` cannot run on every host (on
//! one development host rustdoc re-execs a `rustc` that sits on a `noexec`
//! mount). This file compiles the same shapes against the real crate, so the
//! claim "it is usable as a library" is checked by `cargo test` rather than by
//! reading the README.
//!
//! Nothing here runs a tunnel: these are type and borrow checks. The live proofs
//! are `examples/warp_prove.rs` and `examples/warp_tunnel.rs`.

use std::net::SocketAddr;

use cfrs::warp::{Identity, MasqueSession, StackConfig, WarpClient, WarpStack};
use cfrs::{Service, Transport, Tunnel};

/// The `lib.rs` example: a quick tunnel around an HTTP origin.
async fn quick_tunnel_example() -> anyhow::Result<()> {
    let handle = Tunnel::quick()
        .service(Service::parse("http://127.0.0.1:8080")?)
        .build()?
        .start()
        .await?;
    println!("{:?}", handle.url());
    handle.shutdown().await;
    Ok(())
}

/// The same, with the transport chosen explicitly.
async fn explicit_transport_example() -> anyhow::Result<()> {
    for transport in [Transport::Auto, Transport::Direct, Transport::Warp] {
        let handle = Tunnel::quick()
            .service(Service::parse("http://127.0.0.1:8080")?)
            .transport(transport)
            .build()?
            .start()
            .await?;
        handle.shutdown().await;
    }
    Ok(())
}

/// The `warp` module example: register anonymously, then open the tunnel.
async fn warp_client_example() -> anyhow::Result<()> {
    let client = WarpClient::register().await?;
    let stack: WarpStack = client.connect().await?;
    let conn = stack.tcp_connect("198.41.192.27:7844".parse()?).await?;
    conn.close().await;
    Ok(())
}

/// The pieces a caller needs to persist and resume an identity.
fn identity_example() -> anyhow::Result<()> {
    let identity = Identity::generate()?;
    let spki = identity.spki_b64().to_string();
    assert!(!spki.is_empty());
    assert_eq!(identity.cert_chain().len(), 1);
    let _ = StackConfig::new("172.16.0.2".parse()?);
    Ok(())
}

/// The raw session, for callers that want the packet pipe without the stack.
async fn raw_session_example(addr: SocketAddr) -> anyhow::Result<()> {
    let identity = Identity::generate()?;
    let _session: MasqueSession = MasqueSession::connect(addr, &identity, None).await?;
    Ok(())
}

#[test]
fn the_documented_library_shapes_compile() {
    // Referencing the functions is enough to prove they type-check; running them
    // would open a tunnel, which is what the examples are for.
    let _ = (
        quick_tunnel_example,
        explicit_transport_example,
        warp_client_example,
        raw_session_example,
    );
    identity_example().expect("the identity helpers are local and must work");
}

#[test]
fn the_transport_default_is_the_one_the_readme_describes() {
    assert_eq!(Transport::default(), Transport::Auto);
    assert_eq!(Transport::parse("auto").unwrap(), Transport::Auto);
    assert_eq!(Transport::parse("warp").unwrap(), Transport::Warp);
}
