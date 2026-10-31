//! A userspace IPv4/IPv6 stack over a MASQUE CONNECT-IP session.
//!
//! The point of this module is that nothing it carries touches the host's
//! socket layer. A packet handed to [`WarpStack::tcp_connect`] is built by
//! `smoltcp`, encapsulated in a CONNECT-IP capsule and written to the HTTP/2
//! request body; the reply arrives the same way and is handed back to
//! `smoltcp`. A destination the host's own firewall refuses — port 7844, say —
//! is therefore reachable, because the host never sees a `connect()` for it.
//!
//! One driver task owns the interface and the socket set. Callers hold a
//! [`WarpStack`], which is a command channel into that task.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::sync::{mpsc, oneshot, Notify};

use crate::vnet::device::LinkDevice;

/// The MTU the tunnel carries. 1280 is the IPv6 minimum and what the WARP
/// client uses; anything larger is dropped by the front door.
pub const TUNNEL_MTU: usize = 1280;

const TCP_BUFFER: usize = 128 * 1024;
const UDP_PACKETS: usize = 64;
const UDP_PAYLOAD: usize = 64 * 1024;

/// A live handle on the userspace stack.
pub struct WarpStack {
    cmd: mpsc::Sender<Command>,
    notify: std::sync::Arc<Notify>,
    closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

enum Command {
    TcpConnect {
        remote: SocketAddr,
        reply: oneshot::Sender<Result<u32>>,
    },
    TcpSend {
        id: u32,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<usize>>,
    },
    TcpRecv {
        id: u32,
        max: usize,
        reply: oneshot::Sender<Result<Vec<u8>>>,
    },
    TcpClose {
        id: u32,
    },
    UdpBind {
        reply: oneshot::Sender<Result<u32>>,
    },
    UdpSend {
        id: u32,
        data: Vec<u8>,
        to: SocketAddr,
        reply: oneshot::Sender<Result<usize>>,
    },
    UdpRecv {
        id: u32,
        max: usize,
        reply: oneshot::Sender<Result<(Vec<u8>, SocketAddr)>>,
    },
}

enum Pending {
    TcpConnect {
        id: u32,
        handle: SocketHandle,
        reply: oneshot::Sender<Result<u32>>,
    },
    TcpSend {
        handle: SocketHandle,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<usize>>,
    },
    TcpRecv {
        handle: SocketHandle,
        max: usize,
        reply: oneshot::Sender<Result<Vec<u8>>>,
    },
    UdpSend {
        handle: SocketHandle,
        data: Vec<u8>,
        to: IpEndpoint,
        reply: oneshot::Sender<Result<usize>>,
    },
    UdpRecv {
        handle: SocketHandle,
        max: usize,
        reply: oneshot::Sender<Result<(Vec<u8>, SocketAddr)>>,
    },
}

/// How to configure the interface the tunnel exposes.
pub struct StackConfig {
    /// The address the tunnel assigned to us.
    pub local: IpAddr,
    /// The next hop for everything not on-link. The tunnel is point to point,
    /// so any address in the assigned subnet works; WARP uses `.1`.
    pub gateway: IpAddr,
    pub mtu: usize,
}

impl StackConfig {
    pub fn new(local: IpAddr) -> Self {
        let gateway = match local {
            IpAddr::V4(v4) => {
                let mut o = v4.octets();
                o[3] = 1;
                IpAddr::V4(o.into())
            }
            IpAddr::V6(v6) => IpAddr::V6(v6),
        };
        Self {
            local,
            gateway,
            mtu: TUNNEL_MTU,
        }
    }
}

fn to_smol(addr: IpAddr) -> IpAddress {
    match addr {
        IpAddr::V4(v4) => IpAddress::Ipv4(v4.into()),
        IpAddr::V6(v6) => IpAddress::Ipv6(v6.into()),
    }
}

fn to_endpoint(addr: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(to_smol(addr.ip()), addr.port())
}

fn from_endpoint(ep: IpEndpoint) -> SocketAddr {
    match ep.addr {
        IpAddress::Ipv4(v4) => SocketAddr::new(IpAddr::V4(v4.into()), ep.port),
        IpAddress::Ipv6(v6) => SocketAddr::new(IpAddr::V6(v6.into()), ep.port),
    }
}

impl WarpStack {
    /// Start the stack over an established session.
    pub fn start(
        tx: super::session::MasqueTx,
        rx: super::session::MasqueRx,
        config: StackConfig,
    ) -> Result<Self> {
        let mut device = LinkDevice::tunnel(config.mtu);
        let inbound = device.inbound();
        let outbound = device.outbound();

        let mut iface_config = IfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = 0x0c_f2_5e_ed_00_00_00_01;
        let mut iface = Interface::new(iface_config, &mut device, Instant::ZERO);

        iface.update_ip_addrs(|addrs| {
            let cidr = match config.local {
                IpAddr::V4(v4) => IpCidr::new(IpAddress::Ipv4(v4.into()), 32),
                IpAddr::V6(v6) => IpCidr::new(IpAddress::Ipv6(v6.into()), 128),
            };
            addrs.push(cidr).ok();
        });
        match config.gateway {
            IpAddr::V4(gw) => {
                iface.routes_mut().add_default_ipv4_route(gw.into()).ok();
            }
            IpAddr::V6(gw) => {
                iface.routes_mut().add_default_ipv6_route(gw.into()).ok();
            }
        }

        let sockets: SocketSet<'static> = SocketSet::new(Vec::new());
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let notify = std::sync::Arc::new(Notify::new());
        let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        {
            let notify = notify.clone();
            tokio::spawn(async move {
                let mut tx = tx;
                loop {
                    let packet = outbound.recv().await;
                    if tx.send_packet(&packet).is_err() {
                        break;
                    }
                    notify.notify_one();
                }
            });
        }

        {
            let notify = notify.clone();
            let inbound = inbound.clone();
            let closed = closed.clone();
            tokio::spawn(async move {
                let mut rx = rx;
                loop {
                    match rx.recv_packet().await {
                        Ok(Some(packet)) => {
                            inbound.push(packet.to_vec());
                            notify.notify_one();
                        }
                        Ok(None) => break,
                        Err(err) => {
                            tracing::debug!(%err, "MASQUE receive loop ended");
                            break;
                        }
                    }
                }
                closed.store(true, std::sync::atomic::Ordering::Relaxed);
                notify.notify_one();
            });
        }

        {
            let notify = notify.clone();
            let closed = closed.clone();
            tokio::spawn(async move {
                let mut driver = Driver {
                    iface,
                    sockets,
                    device,
                    registry: HashMap::new(),
                    pending: VecDeque::new(),
                    next_id: 1,
                    next_ephemeral: 40_000,
                };
                driver.run(cmd_rx, notify, closed).await;
            });
        }

        Ok(Self {
            cmd: cmd_tx,
            notify,
            closed,
        })
    }

    fn alive(&self) -> Result<()> {
        if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
            bail!("the MASQUE session is closed");
        }
        Ok(())
    }

    /// Open a TCP connection to `remote` through the tunnel.
    pub async fn tcp_connect(&self, remote: SocketAddr) -> Result<TcpConn> {
        self.alive()?;
        let (reply, wait) = oneshot::channel();
        self.cmd
            .send(Command::TcpConnect { remote, reply })
            .await
            .context("userspace stack driver is gone")?;
        self.notify.notify_one();
        let id = wait.await.context("userspace stack driver is gone")??;
        Ok(TcpConn {
            id,
            cmd: self.cmd.clone(),
            notify: self.notify.clone(),
        })
    }

    /// Bind a UDP socket on the tunnel.
    pub async fn udp_bind(&self) -> Result<UdpConn> {
        self.alive()?;
        let (reply, wait) = oneshot::channel();
        self.cmd
            .send(Command::UdpBind { reply })
            .await
            .context("userspace stack driver is gone")?;
        self.notify.notify_one();
        let id = wait.await.context("userspace stack driver is gone")??;
        Ok(UdpConn {
            id,
            cmd: self.cmd.clone(),
            notify: self.notify.clone(),
        })
    }
}

/// A TCP connection carried by the userspace stack.
pub struct TcpConn {
    id: u32,
    cmd: mpsc::Sender<Command>,
    notify: std::sync::Arc<Notify>,
}

impl TcpConn {
    pub async fn send(&self, data: Vec<u8>) -> Result<usize> {
        let (reply, wait) = oneshot::channel();
        self.cmd
            .send(Command::TcpSend {
                id: self.id,
                data,
                reply,
            })
            .await
            .context("userspace stack driver is gone")?;
        self.notify.notify_one();
        wait.await.context("userspace stack driver is gone")?
    }

    /// Read up to `max` bytes. An empty vector means the peer closed.
    pub async fn recv(&self, max: usize) -> Result<Vec<u8>> {
        let (reply, wait) = oneshot::channel();
        self.cmd
            .send(Command::TcpRecv {
                id: self.id,
                max,
                reply,
            })
            .await
            .context("userspace stack driver is gone")?;
        self.notify.notify_one();
        wait.await.context("userspace stack driver is gone")?
    }

    pub async fn close(&self) {
        let _ = self.cmd.send(Command::TcpClose { id: self.id }).await;
        self.notify.notify_one();
    }
}

/// A UDP socket carried by the userspace stack.
#[derive(Clone)]
pub struct UdpConn {
    id: u32,
    cmd: mpsc::Sender<Command>,
    notify: std::sync::Arc<Notify>,
}

impl UdpConn {
    pub async fn send_to(&self, data: Vec<u8>, to: SocketAddr) -> Result<usize> {
        let (reply, wait) = oneshot::channel();
        self.cmd
            .send(Command::UdpSend {
                id: self.id,
                data,
                to,
                reply,
            })
            .await
            .context("userspace stack driver is gone")?;
        self.notify.notify_one();
        wait.await.context("userspace stack driver is gone")?
    }

    pub async fn recv_from(&self, max: usize) -> Result<(Vec<u8>, SocketAddr)> {
        let (reply, wait) = oneshot::channel();
        self.cmd
            .send(Command::UdpRecv {
                id: self.id,
                max,
                reply,
            })
            .await
            .context("userspace stack driver is gone")?;
        self.notify.notify_one();
        wait.await.context("userspace stack driver is gone")?
    }
}

struct Driver {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: LinkDevice,
    registry: HashMap<u32, SocketHandle>,
    pending: VecDeque<Pending>,
    next_id: u32,
    next_ephemeral: u16,
}

impl Driver {
    fn now() -> Instant {
        use std::sync::OnceLock;
        static START: OnceLock<std::time::Instant> = OnceLock::new();
        let start = START.get_or_init(std::time::Instant::now);
        Instant::from_micros(start.elapsed().as_micros() as i64)
    }

    async fn run(
        &mut self,
        mut cmd_rx: mpsc::Receiver<Command>,
        notify: std::sync::Arc<Notify>,
        closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        loop {
            while let Ok(cmd) = cmd_rx.try_recv() {
                self.apply(cmd);
            }

            let now = Self::now();
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            self.progress();

            if closed.load(std::sync::atomic::Ordering::Relaxed) && self.pending.is_empty() {
                break;
            }

            let delay = self
                .iface
                .poll_delay(now, &self.sockets)
                .map(|d| Duration::from_millis(d.total_millis().max(1)))
                .unwrap_or(Duration::from_millis(50))
                .min(Duration::from_millis(50));

            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = notify.notified() => {}
                cmd = cmd_rx.recv() => match cmd {
                    Some(cmd) => self.apply(cmd),
                    None => break,
                },
            }
        }
    }

    fn tcp_socket() -> tcp::Socket<'static> {
        tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
        )
    }

    fn udp_socket() -> udp::Socket<'static> {
        udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0u8; UDP_PAYLOAD],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0u8; UDP_PAYLOAD],
            ),
        )
    }

    fn handle_of(&self, id: u32) -> Option<SocketHandle> {
        self.registry.get(&id).copied()
    }

    fn apply(&mut self, cmd: Command) {
        match cmd {
            Command::TcpConnect { remote, reply } => {
                let id = self.next_id;
                self.next_id += 1;
                let local_port = self.next_ephemeral;
                self.next_ephemeral = if self.next_ephemeral >= 60_000 {
                    40_000
                } else {
                    self.next_ephemeral + 1
                };

                let local_addr = match remote.ip() {
                    IpAddr::V4(_) => self.iface.ipv4_addr().map(IpAddress::Ipv4),
                    IpAddr::V6(_) => self.iface.ipv6_addr().map(IpAddress::Ipv6),
                };
                let Some(local_addr) = local_addr else {
                    let _ = reply.send(Err(anyhow::anyhow!(
                        "the tunnel has no address for {remote}"
                    )));
                    return;
                };

                let handle = self.sockets.add(Self::tcp_socket());
                let result = {
                    let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                    socket.connect(
                        self.iface.context(),
                        to_endpoint(remote),
                        IpListenEndpoint {
                            addr: Some(local_addr),
                            port: local_port,
                        },
                    )
                };
                if let Err(err) = result {
                    self.sockets.remove(handle);
                    let _ = reply.send(Err(anyhow::anyhow!("connect {remote}: {err}")));
                    return;
                }
                self.registry.insert(id, handle);
                self.pending.push_back(Pending::TcpConnect { id, handle, reply });
            }

            Command::TcpSend { id, data, reply } => match self.handle_of(id) {
                Some(handle) => self
                    .pending
                    .push_back(Pending::TcpSend { handle, data, reply }),
                None => {
                    let _ = reply.send(Err(anyhow::anyhow!("no such connection {id}")));
                }
            },

            Command::TcpRecv { id, max, reply } => match self.handle_of(id) {
                Some(handle) => self
                    .pending
                    .push_back(Pending::TcpRecv { handle, max, reply }),
                None => {
                    let _ = reply.send(Err(anyhow::anyhow!("no such connection {id}")));
                }
            },

            Command::TcpClose { id } => {
                if let Some(handle) = self.registry.remove(&id) {
                    self.sockets.get_mut::<tcp::Socket>(handle).close();
                }
            }

            Command::UdpBind { reply } => {
                let id = self.next_id;
                self.next_id += 1;
                let local_port = self.next_ephemeral;
                self.next_ephemeral = if self.next_ephemeral >= 60_000 {
                    40_000
                } else {
                    self.next_ephemeral + 1
                };
                let local_addr = self
                    .iface
                    .ipv4_addr()
                    .map(IpAddress::Ipv4)
                    .or_else(|| self.iface.ipv6_addr().map(IpAddress::Ipv6));
                let Some(local_addr) = local_addr else {
                    let _ = reply.send(Err(anyhow::anyhow!("the tunnel has no address")));
                    return;
                };
                let handle = self.sockets.add(Self::udp_socket());
                let result = {
                    let socket = self.sockets.get_mut::<udp::Socket>(handle);
                    socket.bind(IpListenEndpoint {
                        addr: Some(local_addr),
                        port: local_port,
                    })
                };
                if let Err(err) = result {
                    self.sockets.remove(handle);
                    let _ = reply.send(Err(anyhow::anyhow!("udp bind: {err}")));
                    return;
                }
                self.registry.insert(id, handle);
                let _ = reply.send(Ok(id));
            }

            Command::UdpSend { id, data, to, reply } => match self.handle_of(id) {
                Some(handle) => self.pending.push_back(Pending::UdpSend {
                    handle,
                    data,
                    to: to_endpoint(to),
                    reply,
                }),
                None => {
                    let _ = reply.send(Err(anyhow::anyhow!("no such socket {id}")));
                }
            },

            Command::UdpRecv { id, max, reply } => match self.handle_of(id) {
                Some(handle) => self
                    .pending
                    .push_back(Pending::UdpRecv { handle, max, reply }),
                None => {
                    let _ = reply.send(Err(anyhow::anyhow!("no such socket {id}")));
                }
            },
        }
    }

    fn progress(&mut self) {
        let mut still_waiting = VecDeque::with_capacity(self.pending.len());
        while let Some(op) = self.pending.pop_front() {
            match op {
                Pending::TcpConnect { id, handle, reply } => {
                    let state = self.sockets.get_mut::<tcp::Socket>(handle).state();
                    match state {
                        tcp::State::Established => {
                            let _ = reply.send(Ok(id));
                        }
                        tcp::State::Closed | tcp::State::TimeWait => {
                            self.registry.remove(&id);
                            self.sockets.remove(handle);
                            let _ = reply.send(Err(anyhow::anyhow!(
                                "connection refused or reset"
                            )));
                        }
                        _ => still_waiting.push_back(Pending::TcpConnect { id, handle, reply }),
                    }
                }
                Pending::TcpSend {
                    handle,
                    mut data,
                    reply,
                } => {
                    let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                    if socket.can_send() {
                        match socket.send_slice(&data) {
                            Ok(sent) => {
                                data.drain(..sent);
                                if data.is_empty() {
                                    let _ = reply.send(Ok(sent));
                                } else {
                                    still_waiting.push_back(Pending::TcpSend {
                                        handle,
                                        data,
                                        reply,
                                    });
                                }
                            }
                            Err(err) => {
                                let _ = reply.send(Err(anyhow::anyhow!("tcp send: {err}")));
                            }
                        }
                    } else if !socket.may_send() {
                        let _ = reply.send(Err(anyhow::anyhow!("connection closed")));
                    } else {
                        still_waiting.push_back(Pending::TcpSend {
                            handle,
                            data,
                            reply,
                        });
                    }
                }
                Pending::TcpRecv {
                    handle,
                    max,
                    reply,
                } => {
                    let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                    if socket.can_recv() {
                        let mut buf = vec![0u8; max];
                        match socket.recv_slice(&mut buf) {
                            Ok(n) => {
                                buf.truncate(n);
                                let _ = reply.send(Ok(buf));
                            }
                            Err(err) => {
                                let _ = reply.send(Err(anyhow::anyhow!("tcp recv: {err}")));
                            }
                        }
                    } else if !socket.may_recv() {
                        let _ = reply.send(Ok(Vec::new()));
                    } else {
                        still_waiting.push_back(Pending::TcpRecv {
                            handle,
                            max,
                            reply,
                        });
                    }
                }
                Pending::UdpSend {
                    handle,
                    data,
                    to,
                    reply,
                } => {
                    let socket = self.sockets.get_mut::<udp::Socket>(handle);
                    let len = data.len();
                    match socket.send_slice(&data, to) {
                        Ok(()) => {
                            let _ = reply.send(Ok(len));
                        }
                        Err(udp::SendError::BufferFull) => {
                            still_waiting.push_back(Pending::UdpSend {
                                handle,
                                data,
                                to,
                                reply,
                            });
                        }
                        Err(err) => {
                            let _ = reply.send(Err(anyhow::anyhow!("udp send: {err}")));
                        }
                    }
                }
                Pending::UdpRecv {
                    handle,
                    max,
                    reply,
                } => {
                    let socket = self.sockets.get_mut::<udp::Socket>(handle);
                    if socket.can_recv() {
                        let mut buf = vec![0u8; max];
                        match socket.recv_slice(&mut buf) {
                            Ok((n, from)) => {
                                buf.truncate(n);
                                let _ = reply.send(Ok((buf, from_endpoint(from.endpoint))));
                            }
                            Err(err) => {
                                let _ = reply.send(Err(anyhow::anyhow!("udp recv: {err}")));
                            }
                        }
                    } else {
                        still_waiting.push_back(Pending::UdpRecv {
                            handle,
                            max,
                            reply,
                        });
                    }
                }
            }
        }
        self.pending = still_waiting;
    }
}
