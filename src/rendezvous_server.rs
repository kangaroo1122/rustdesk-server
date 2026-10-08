use crate::common::*;
use crate::peer::*;
use crate::protocol::rendezvous::{
    register_pk_response::Result::{INVALID_ID_FORMAT, TOO_FREQUENT, UUID_MISMATCH},
    *,
};
use crate::{
    handshake::Handshake,
    signaling::{Routes, MAX_SIGNAL_BYTES},
};
use hbb_common::{
    allow_err, bail,
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    config,
    futures::future::join_all,
    futures_util::{
        sink::SinkExt,
        stream::{SplitSink, StreamExt},
    },
    log,
    protobuf::{Message as _, MessageField},
    sodiumoxide::crypto::sign,
    tcp::Encrypt,
    tcp::{listen_any, FramedStream},
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{mpsc, Mutex, Semaphore},
        time::{interval, Duration},
    },
    tokio_util::codec::Framed,
    try_into_v4,
    udp::FramedSocket,
    AddrMangle, ResultType,
};
use ipnetwork::Ipv4Network;
use serde_derive::Deserialize;

use crate::jwt;
use once_cell::sync::Lazy;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::Arc,
    time::Instant,
};

#[derive(Clone, Debug)]
enum Data {
    Msg(Box<RendezvousMessage>, SocketAddr),
    RelayServers0(String),
    RelayServers(RelayServers),
}

const REG_TIMEOUT: i64 = 30_000;
const MANAGEMENT_REQUEST_LIMIT: usize = 1024;
const MANAGEMENT_RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
type TcpStreamSink = SplitSink<Framed<TcpStream, BytesCodec>, Bytes>;
type WsSink = SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, tungstenite::Message>;
struct SafeWsSink {
    sink: WsSink,
    encrypt: Option<Encrypt>,
}

struct SafeTcpStreamSink {
    sink: TcpStreamSink,
    encrypt: Option<Encrypt>,
}
enum Sink {
    // TcpStream(TcpStreamSink),
    // Ws(WsSink),
    Wss(SafeWsSink),
    Tss(SafeTcpStreamSink),
}

#[derive(Debug, Default, Deserialize)]
struct RegistryRequest {
    operation: String,
    #[serde(default)]
    page: Option<u32>,
    #[serde(default)]
    page_size: Option<u32>,
    #[serde(default)]
    keyword: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    public_key_fingerprint: Option<String>,
    #[serde(default)]
    force: bool,
}

fn registry_success<T: serde::Serialize>(data: T) -> String {
    serde_json::json!({
        "version": 1,
        "success": true,
        "data": data,
    })
    .to_string()
}

fn registry_error(code: &str, message: &str) -> String {
    serde_json::json!({
        "version": 1,
        "success": false,
        "error": {
            "code": code,
            "message": message,
        },
    })
    .to_string()
}

fn valid_registry_id(id: Option<String>) -> Option<String> {
    id.filter(|value| {
        !value.is_empty()
            && value.len() <= 100
            && !value.chars().any(|character| character.is_control())
    })
}

impl Sink {
    async fn send(&mut self, msg: &RendezvousMessage) {
        if let Ok(mut bytes) = msg.write_to_bytes() {
            match self {
                // Sink::TcpStream(mut s) => allow_err!(s.send(Bytes::from(bytes)).await),
                // Sink::Ws(mut s) => allow_err!(s.send(tungstenite::Message::Binary(bytes)).await),
                Sink::Wss(s) => {
                    if let Some(key) = s.encrypt.as_mut() {
                        bytes = key.enc(&bytes);
                    }
                    allow_err!(s.sink.send(tungstenite::Message::Binary(bytes)).await)
                }
                Sink::Tss(s) => {
                    if let Some(key) = s.encrypt.as_mut() {
                        bytes = key.enc(&bytes);
                    }
                    allow_err!(s.sink.send(Bytes::from(bytes)).await)
                }
            }
        }
    }
}
type Sender = mpsc::UnboundedSender<Data>;
type Receiver = mpsc::UnboundedReceiver<Data>;
static ROTATION_RELAY_SERVER: AtomicUsize = AtomicUsize::new(0);
type RelayServers = Vec<String>;
const CHECK_RELAY_TIMEOUT: u64 = 3_000;
static ALWAYS_USE_RELAY: AtomicBool = AtomicBool::new(false);
static MUST_LOGIN: AtomicBool = AtomicBool::new(false);
const PUNCH_REQ_TTL_SECS: u64 = 24 * 60 * 60;
const MAX_PUNCH_REQS: usize = 10_000;
static API_UDP_SLOTS: Lazy<Arc<Semaphore>> = Lazy::new(|| Arc::new(Semaphore::new(128)));
static SIGNALING_SLOTS: Lazy<Arc<Semaphore>> = Lazy::new(|| Arc::new(Semaphore::new(4096)));

#[derive(Clone)]
struct PunchReqEntry {
    tm: Instant,
    from_ip: String,
    to_ip: String,
    to_id: String,
}

static PUNCH_REQS: Lazy<Mutex<VecDeque<PunchReqEntry>>> = Lazy::new(|| Mutex::new(VecDeque::new()));

#[derive(Clone)]
struct Inner {
    serial: i32,
    version: String,
    software_url: String,
    mask: Option<Ipv4Network>,
    local_ip: String,
    sk: Option<sign::SecretKey>,
}

#[derive(Clone)]
pub struct RendezvousServer {
    tcp_punch: Arc<Mutex<HashMap<SocketAddr, Arc<Mutex<Sink>>>>>,
    ice_routes: Arc<Mutex<Routes>>,
    pm: PeerMap,
    tx: Sender,
    relay_servers: Arc<RelayServers>,
    relay_servers0: Arc<RelayServers>,
    rendezvous_servers: Arc<Vec<String>>,
    inner: Arc<Inner>,
    ws_map: Arc<Mutex<HashMap<SocketAddr, Arc<Mutex<Sink>>>>>,
}

enum LoopFailure {
    UdpSocket,
    Listener3,
    Listener2,
    Listener,
}

impl RendezvousServer {
    #[tokio::main(flavor = "multi_thread")]
    pub async fn start(port: i32, serial: i32, key: &str, rmem: usize) -> ResultType<()> {
        let (key, sk) = Self::get_server_sk(key);
        let nat_port = port - 1;
        let ws_port = port + 2;
        let pm = PeerMap::new().await?;
        log::info!("serial={}", serial);
        let rendezvous_servers = get_servers(&get_arg("rendezvous-servers"), "rendezvous-servers");
        log::info!("Listening on tcp/udp :{}", port);
        log::info!("Listening on tcp :{}, extra port for NAT test", nat_port);
        log::info!("Listening on websocket :{}", ws_port);
        let mut socket = create_udp_listener(port, rmem).await?;
        let (tx, mut rx) = mpsc::unbounded_channel::<Data>();
        let software_url = get_arg("software-url");
        let version = hbb_common::get_version_from_url(&software_url);
        if !version.is_empty() {
            log::info!("software_url: {}, version: {}", software_url, version);
        }
        let mask = get_arg("mask").parse().ok();
        let local_ip = if mask.is_none() {
            "".to_owned()
        } else {
            get_arg_or(
                "local-ip",
                local_ip_address::local_ip()
                    .map(|x| x.to_string())
                    .unwrap_or_default(),
            )
        };
        let mut rs = Self {
            tcp_punch: Arc::new(Mutex::new(HashMap::new())),
            ice_routes: Default::default(),
            pm,
            tx: tx.clone(),
            relay_servers: Default::default(),
            relay_servers0: Default::default(),
            rendezvous_servers: Arc::new(rendezvous_servers),
            inner: Arc::new(Inner {
                serial,
                version,
                software_url,
                sk,
                mask,
                local_ip,
            }),
            ws_map: Arc::new(Mutex::new(HashMap::new())),
        };
        log::info!("mask: {:?}", rs.inner.mask);
        log::info!("local-ip: {:?}", rs.inner.local_ip);
        std::env::set_var("PORT_FOR_API", port.to_string());
        rs.parse_relay_servers(&get_arg("relay-servers"));
        let mut listener = create_tcp_listener(port).await?;
        let mut listener2 = create_tcp_listener(nat_port).await?;
        let mut listener3 = create_tcp_listener(ws_port).await?;
        let test_addr = std::env::var("TEST_HBBS").unwrap_or_default();
        if std::env::var("ALWAYS_USE_RELAY")
            .unwrap_or_default()
            .to_uppercase()
            == "Y"
        {
            ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
        }
        log::info!(
            "ALWAYS_USE_RELAY={}",
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) {
                "Y"
            } else {
                "N"
            }
        );

        let must_login = get_arg("must-login");
        log::debug!("must_login={}", must_login);
        if must_login.to_uppercase() == "Y"
            || (must_login.is_empty()
                && std::env::var("MUST_LOGIN")
                    .unwrap_or_default()
                    .to_uppercase()
                    == "Y")
        {
            MUST_LOGIN.store(true, Ordering::SeqCst);
        }

        log::info!(
            "MUST_LOGIN={}",
            if MUST_LOGIN.load(Ordering::SeqCst) {
                "Y"
            } else {
                "N"
            }
        );
        if test_addr.to_lowercase() != "no" {
            let test_addr = if test_addr.is_empty() {
                listener.local_addr()?
            } else {
                test_addr.parse()?
            };
            tokio::spawn(async move {
                if let Err(err) = test_hbbs(test_addr).await {
                    if test_addr.is_ipv6() && test_addr.ip().is_unspecified() {
                        let mut test_addr = test_addr;
                        test_addr.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                        if let Err(err) = test_hbbs(test_addr).await {
                            log::error!("Failed to run hbbs test with {test_addr}: {err}");
                            std::process::exit(1);
                        }
                    } else {
                        log::error!("Failed to run hbbs test with {test_addr}: {err}");
                        std::process::exit(1);
                    }
                }
            });
        };
        let main_task = async move {
            loop {
                log::info!("Start");
                match rs
                    .io_loop(
                        &mut rx,
                        &mut listener,
                        &mut listener2,
                        &mut listener3,
                        &mut socket,
                        &key,
                    )
                    .await
                {
                    LoopFailure::UdpSocket => {
                        drop(socket);
                        socket = create_udp_listener(port, rmem).await?;
                    }
                    LoopFailure::Listener => {
                        drop(listener);
                        listener = create_tcp_listener(port).await?;
                    }
                    LoopFailure::Listener2 => {
                        drop(listener2);
                        listener2 = create_tcp_listener(nat_port).await?;
                    }
                    LoopFailure::Listener3 => {
                        drop(listener3);
                        listener3 = create_tcp_listener(ws_port).await?;
                    }
                }
            }
        };
        let listen_signal = listen_signal();
        tokio::select!(
            res = main_task => res,
            res = listen_signal => res,
        )
    }

    async fn io_loop(
        &mut self,
        rx: &mut Receiver,
        listener: &mut TcpListener,
        listener2: &mut TcpListener,
        listener3: &mut TcpListener,
        socket: &mut FramedSocket,
        key: &str,
    ) -> LoopFailure {
        let mut timer_check_relay = interval(Duration::from_millis(CHECK_RELAY_TIMEOUT));
        loop {
            tokio::select! {
                _ = timer_check_relay.tick() => {
                    if self.relay_servers0.len() > 1 {
                        let rs = self.relay_servers0.clone();
                        let tx = self.tx.clone();
                        tokio::spawn(async move {
                            check_relay_servers(rs, tx).await;
                        });
                    }
                }
                Some(data) = rx.recv() => {
                    match data {
                        Data::Msg(msg, addr) => { allow_err!(socket.send(msg.as_ref(), addr).await); }
                        Data::RelayServers0(rs) => { self.parse_relay_servers(&rs); }
                        Data::RelayServers(rs) => { self.relay_servers = Arc::new(rs); }
                    }
                }
                res = socket.next() => {
                    match res {
                        Some(Ok((bytes, addr))) => {
                            if let Err(err) = self.handle_udp(&bytes, addr.into(), socket, key).await {
                                log::error!("udp failure: {}", err);
                                return LoopFailure::UdpSocket;
                            }
                        }
                        Some(Err(err)) => {
                            log::error!("udp failure: {}", err);
                            return LoopFailure::UdpSocket;
                        }
                        None => {
                            // unreachable!() ?
                        }
                    }
                }
                res = listener2.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("listener2.accept failed: {}", err);
                           return LoopFailure::Listener2;
                        }
                    }
                }
                res = listener3.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, true).await;
                        }
                        Err(err) => {
                           log::error!("listener3.accept failed: {}", err);
                           return LoopFailure::Listener3;
                        }
                    }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, addr)) => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, false).await;
                        }
                       Err(err) => {
                           log::error!("listener.accept failed: {}", err);
                           return LoopFailure::Listener;
                       }
                    }
                }
            }
        }
    }

    #[inline]
    async fn handle_udp(
        &mut self,
        bytes: &BytesMut,
        addr: SocketAddr,
        socket: &mut FramedSocket,
        key: &str,
    ) -> ResultType<()> {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            if crate::api_bridge::configured()
                && matches!(
                    msg_in.union,
                    Some(rendezvous_message::Union::RegisterPeer(_))
                        | Some(rendezvous_message::Union::RegisterPk(_))
                        | Some(rendezvous_message::Union::PunchHoleRequest(_))
                )
            {
                // HTTP admission must not stall UDP traffic or the management listener.
                if let Ok(permit) = API_UDP_SLOTS.clone().try_acquire_owned() {
                    let mut server = self.clone();
                    let key = key.to_owned();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(err) = server.handle_api_udp(msg_in, addr, &key).await {
                            log::trace!("API UDP request failed: {err}");
                        }
                    });
                }
                return Ok(());
            }
            match msg_in.union {
                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    // B registered
                    if !rp.id.is_empty() {
                        log::trace!("New peer registered: {:?} {:?}", rp.id, addr);
                        let request_pk = self.update_addr(rp.id, addr).await;
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_register_peer_response(RegisterPeerResponse {
                            request_pk,
                            ..Default::default()
                        });
                        socket.send(&msg_out, addr).await?;
                        if self.inner.serial > rp.serial {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_configure_update(ConfigUpdate {
                                serial: self.inner.serial,
                                rendezvous_servers: (*self.rendezvous_servers).clone(),
                                ..Default::default()
                            });
                            socket.send(&msg_out, addr).await?;
                        }
                    }
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    let response = self.handle_register_pk(rk, addr, false).await;
                    match response {
                        Err(err) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_register_pk_response(RegisterPkResponse {
                                result: err.into(),
                                ..Default::default()
                            });
                            socket.send(&msg_out, addr).await?;
                        }
                        Ok(res) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_register_pk_response(RegisterPkResponse {
                                result: res.into(),
                                ..Default::default()
                            });
                            socket.send(&msg_out, addr).await?;
                        }
                    }
                }
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    if !ph.webrtc_sdp_offer.is_empty() {
                        return Ok(());
                    }
                    if self.pm.is_in_memory(&ph.id).await {
                        self.handle_udp_punch_hole_request(addr, ph, key).await?;
                    } else {
                        // Fetch a peer not yet loaded into memory without blocking the UDP loop.
                        let mut me = self.clone();
                        let key = key.to_owned();
                        tokio::spawn(async move {
                            allow_err!(me.handle_udp_punch_hole_request(addr, ph, &key).await);
                        });
                    }
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    self.handle_hole_sent(phs, addr, Some(socket)).await?;
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    self.handle_local_addr(la, addr, Some(socket)).await?;
                }
                Some(rendezvous_message::Union::ConfigureUpdate(mut cu)) => {
                    if try_into_v4(addr).ip().is_loopback() && cu.serial > self.inner.serial {
                        let mut inner: Inner = (*self.inner).clone();
                        inner.serial = cu.serial;
                        self.inner = Arc::new(inner);
                        self.rendezvous_servers = Arc::new(
                            cu.rendezvous_servers
                                .drain(..)
                                .filter(|x| {
                                    !x.is_empty()
                                        && test_if_valid_server(x, "rendezvous-server").is_ok()
                                })
                                .collect(),
                        );
                        log::info!(
                            "configure updated: serial={} rendezvous-servers={:?}",
                            self.inner.serial,
                            self.rendezvous_servers
                        );
                    }
                }
                Some(rendezvous_message::Union::SoftwareUpdate(su))
                    if !self.inner.version.is_empty() && su.url != self.inner.version =>
                {
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_software_update(SoftwareUpdate {
                        url: self.inner.software_url.clone(),
                        ..Default::default()
                    });
                    socket.send(&msg_out, addr).await?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn handle_api_udp(
        &mut self,
        message: RendezvousMessage,
        addr: SocketAddr,
        key: &str,
    ) -> ResultType<()> {
        let mut reply = RendezvousMessage::new();
        match message.union {
            Some(rendezvous_message::Union::RegisterPeer(rp)) if !rp.id.is_empty() => {
                reply.set_register_peer_response(RegisterPeerResponse {
                    request_pk: self.update_addr(rp.id, addr).await,
                    ..Default::default()
                });
                self.tx.send(Data::Msg(reply.into(), addr))?;
                if self.inner.serial > rp.serial {
                    let mut update = RendezvousMessage::new();
                    update.set_configure_update(ConfigUpdate {
                        serial: self.inner.serial,
                        rendezvous_servers: (*self.rendezvous_servers).clone(),
                        ..Default::default()
                    });
                    self.tx.send(Data::Msg(update.into(), addr))?;
                }
            }
            Some(rendezvous_message::Union::RegisterPk(rk)) => {
                let result = self
                    .handle_register_pk(rk, addr, false)
                    .await
                    .unwrap_or_else(|e| e);
                reply.set_register_pk_response(RegisterPkResponse {
                    result: result.into(),
                    ..Default::default()
                });
                self.tx.send(Data::Msg(reply.into(), addr))?;
            }
            Some(rendezvous_message::Union::PunchHoleRequest(ph))
                if ph.webrtc_sdp_offer.is_empty() =>
            {
                self.handle_udp_punch_hole_request(addr, ph, key).await?;
            }
            _ => {}
        }
        Ok(())
    }

    #[inline]
    async fn handle_tcp(
        &mut self,
        bytes: &[u8],
        sink: &mut Option<Sink>,
        addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> bool {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            // log::debug!("Received TCP message from {}: {:?}", addr, msg_in);
            match msg_in.union {
                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    // B registered
                    if !rp.id.is_empty() {
                        log::trace!("New peer registered: {:?} {:?}", rp.id, addr);
                        let request_pk = self.update_addr(rp.id, addr).await;
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_register_peer_response(RegisterPeerResponse {
                            request_pk,
                            ..Default::default()
                        });
                        self.respond_to_connection(sink, msg_out, addr).await;
                        if self.inner.serial > rp.serial {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_configure_update(ConfigUpdate {
                                serial: self.inner.serial,
                                rendezvous_servers: (*self.rendezvous_servers).clone(),
                                ..Default::default()
                            });
                            self.respond_to_connection(sink, msg_out, addr).await;
                        }
                    }
                    return ws;
                }
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch
                            .lock()
                            .await
                            .insert(try_into_v4(addr), Arc::new(Mutex::new(sink)));
                    }
                    if let Err(err) = self.handle_tcp_punch_hole_request(addr, ph, key, ws).await {
                        log::debug!("Rejected punch request: {err}");
                        return false;
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RequestRelay(mut rf)) => {
                    // Legacy clients omit the key on HBBS relay requests; HBBR verifies it when pairing.
                    if !key.is_empty() && !rf.licence_key.is_empty() && rf.licence_key != key {
                        let mut response = RendezvousMessage::new();
                        response.set_relay_response(RelayResponse {
                            refuse_reason: "Invalid server key".into(),
                            ..Default::default()
                        });
                        self.respond_to_connection(sink, response, addr).await;
                        return false;
                    }
                    let policy = match self
                        .authorize_connection(&rf.id, &rf.token, &rf.switch_code)
                        .await
                    {
                        Ok(policy) => policy,
                        Err(err) => {
                            log::warn!("Relay authorization failed: {err}");
                            let mut response = RendezvousMessage::new();
                            response.set_relay_response(RelayResponse { refuse_reason: "Connection authorization failed; please login or check server policy".into(), ..Default::default() });
                            self.respond_to_connection(sink, response, addr).await;
                            return false;
                        }
                    };
                    rf.control_permissions = policy.permissions().into();
                    rf.controlled_context = policy.context().into();
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch
                            .lock()
                            .await
                            .insert(try_into_v4(addr), Arc::new(Mutex::new(sink)));
                    }
                    if let Some(peer) = self.pm.get_in_memory(&rf.id).await {
                        let mut msg_out = RendezvousMessage::new();
                        rf.socket_addr = AddrMangle::encode(addr).into();
                        msg_out.set_request_relay(rf);
                        let peer_addr = peer.read().await.socket_addr;
                        allow_err!(self.send_to_peer(msg_out, peer_addr).await);
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RelayResponse(mut rr)) => {
                    let addr_b = try_into_v4(AddrMangle::decode(&rr.socket_addr));
                    if !rr.webrtc_sdp_answer.is_empty()
                        && !self
                            .ice_routes
                            .lock()
                            .await
                            .answer_allowed(&addr_b, try_into_v4(addr))
                    {
                        return false;
                    }
                    rr.socket_addr = Default::default();
                    let id = rr.id();
                    if !id.is_empty() {
                        let pk = self.get_pk(&rr.version, id.to_owned()).await;
                        rr.set_pk(pk);
                    }
                    let mut msg_out = RendezvousMessage::new();
                    if !rr.relay_server.is_empty() {
                        if self.is_lan(addr_b) {
                            // https://github.com/rustdesk/rustdesk-server/issues/24
                            rr.relay_server = self.inner.local_ip.clone();
                        } else if rr.relay_server == self.inner.local_ip {
                            rr.relay_server = self.get_relay_server(addr.ip(), addr_b.ip());
                        }
                    }
                    rr.feedback =
                        i32::from(crate::api_bridge::configured() || !jwt::SECRET.is_empty());
                    msg_out.set_relay_response(rr);
                    allow_err!(self.send_to_tcp_sync(msg_out, addr_b).await);
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    allow_err!(self.handle_hole_sent(phs, addr, None).await);
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    allow_err!(self.handle_local_addr(la, addr, None).await);
                }
                Some(rendezvous_message::Union::TestNatRequest(tar)) => {
                    let mut msg_out = RendezvousMessage::new();
                    let mut res = TestNatResponse {
                        port: addr.port() as _,
                        ..Default::default()
                    };
                    if self.inner.serial > tar.serial {
                        let mut cu = ConfigUpdate::new();
                        cu.serial = self.inner.serial;
                        cu.rendezvous_servers = (*self.rendezvous_servers).clone();
                        res.cu = MessageField::from_option(Some(cu));
                    }
                    msg_out.set_test_nat_response(res);
                    self.respond_to_connection(sink, msg_out, addr).await;
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    let response = self.handle_register_pk(rk, addr, ws).await;
                    match response {
                        Err(err) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_register_pk_response(RegisterPkResponse {
                                result: err.into(),
                                ..Default::default()
                            });
                            self.respond_to_connection(sink, msg_out, addr).await;
                            return false;
                        }
                        Ok(res) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_register_pk_response(RegisterPkResponse {
                                result: res.into(),
                                ..Default::default()
                            });
                            self.respond_to_connection(sink, msg_out, addr).await;
                            if ws {
                                // for ws, we can only get addr when register_pk
                                if let Some(sink) = sink.take() {
                                    self.ws_map
                                        .lock()
                                        .await
                                        .insert(try_into_v4(addr), Arc::new(Mutex::new(sink)));
                                }
                            }
                            return true;
                        }
                    }
                }
                Some(rendezvous_message::Union::IceCandidate(ice)) => {
                    return match self.handle_ice(ice, addr).await {
                        Ok(()) => true,
                        Err(err) => {
                            log::debug!("Rejected ICE candidate: {err}");
                            false
                        }
                    };
                }
                Some(rendezvous_message::Union::HttpProxyRequest(request)) => {
                    if ws {
                        return false;
                    }
                    let result = crate::api_bridge::proxy(request, addr.ip()).await;
                    let mut response = RendezvousMessage::new();
                    response.set_http_proxy_response(result.unwrap_or_else(|_| {
                        HttpProxyResponse {
                            status: 502,
                            error: "API proxy unavailable or request rejected".into(),
                            ..Default::default()
                        }
                    }));
                    self.respond_to_connection(sink, response, addr).await;
                }
                Some(rendezvous_message::Union::OnlineRequest(or)) => {
                    let states = self.peers_online_state(or.peers).await;
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_online_response(OnlineResponse {
                        states: states.into(),
                        ..Default::default()
                    });
                    self.respond_to_connection(sink, msg_out, addr).await;
                }
                _ => {}
            }
        }
        false
    }

    async fn authorize_connection(
        &self,
        id: &str,
        token: &str,
        switch_code: &str,
    ) -> ResultType<crate::api_bridge::Policy> {
        let must_login = MUST_LOGIN.load(Ordering::SeqCst);
        if crate::api_bridge::configured() {
            let (uuid, pk) = if let Some(peer) = self.pm.get(id).await {
                let peer = peer.read().await;
                (peer.uuid.clone(), peer.pk.clone())
            } else {
                (Bytes::new(), Bytes::new())
            };
            return crate::api_bridge::authorize(id, token, switch_code, must_login, &uuid, &pk)
                .await;
        }
        if must_login {
            jwt::verify_token(token).map_err(|e| hbb_common::anyhow::anyhow!(e))?;
        }
        Ok(Default::default())
    }

    async fn peers_online_state(&mut self, peers: Vec<String>) -> BytesMut {
        let mut states = BytesMut::zeroed(peers.len().div_ceil(8));
        for (i, peer_id) in peers.iter().enumerate() {
            if let Some(peer) = self.pm.get_in_memory(peer_id).await {
                let elapsed = peer.read().await.last_reg_time.elapsed().as_millis() as i64;
                // bytes index from left to right
                let states_idx = i / 8;
                let bit_idx = 7 - i % 8;
                if elapsed < REG_TIMEOUT {
                    states[states_idx] |= 0x01 << bit_idx;
                }
            }
        }
        states
    }

    async fn handle_register_pk(
        &mut self,
        rk: RegisterPk,
        addr: SocketAddr,
        ws: bool,
    ) -> Result<register_pk_response::Result, register_pk_response::Result> {
        if rk.no_register_device {
            return Err(register_pk_response::Result::NOT_DEPLOYED);
        }
        if crate::api_bridge::configured() {
            // ID-change requests omit pk. Use the registered identity, including retries after rename.
            let admission_pk = if !rk.old_id.is_empty() {
                let peer = match self.pm.get(&rk.old_id).await {
                    Some(peer) => Some(peer),
                    None => self.pm.get(&rk.id).await,
                };
                let Some(peer) = peer else {
                    return Err(UUID_MISMATCH);
                };
                let peer = peer.read().await;
                if peer.uuid != rk.uuid {
                    return Err(UUID_MISMATCH);
                }
                peer.pk.clone()
            } else {
                rk.pk.clone()
            };
            match crate::api_bridge::admitted(&rk.id, &rk.uuid, &admission_pk).await {
                Ok(true) => {}
                Ok(false) => return Err(register_pk_response::Result::NOT_DEPLOYED),
                Err(_) => return Err(register_pk_response::Result::SERVER_ERROR),
            }
        }
        if !rk.old_id.is_empty() {
            if rk.uuid.is_empty() || !hbb_common::is_valid_custom_id(&rk.id) {
                return Err(INVALID_ID_FORMAT);
            }
            let result = self.pm.change_id(&rk.old_id, &rk.id, &rk.uuid).await;
            return if result == register_pk_response::Result::OK {
                Ok(result)
            } else {
                Err(result)
            };
        }
        if rk.uuid.is_empty() || rk.pk.is_empty() {
            return Err(INVALID_ID_FORMAT);
        }
        let id = rk.id;
        let ip = addr.ip().to_string();
        if id.len() < 6 {
            return Err(UUID_MISMATCH);
            //return Err(send_rk_res(socket, addr, UUID_MISMATCH).await);
        } else if !self.check_ip_blocker(&ip, &id).await {
            return Err(TOO_FREQUENT);
            //return Err(send_rk_res(socket, addr, TOO_FREQUENT).await);
        }
        let peer = self.pm.get_or(&id).await;
        let (changed, ip_changed) = {
            let peer = peer.read().await;
            if peer.uuid.is_empty() {
                (true, false)
            } else {
                if peer.uuid == rk.uuid {
                    if peer.info.ip != ip && peer.pk != rk.pk {
                        log::warn!(
                            "Peer {} ip/pk mismatch: {}/{:?} vs {}/{:?}",
                            id,
                            ip,
                            rk.pk,
                            peer.info.ip,
                            peer.pk,
                        );
                        drop(peer);
                        return Err(UUID_MISMATCH);
                        //return Err(send_rk_res(socket, addr, UUID_MISMATCH).await);
                    }
                } else {
                    log::warn!(
                        "Peer {} uuid mismatch: {:?} vs {:?}",
                        id,
                        rk.uuid,
                        peer.uuid
                    );
                    drop(peer);
                    return Err(UUID_MISMATCH);
                    //return Err(send_rk_res(socket, addr, UUID_MISMATCH).await);
                }
                let ip_changed = peer.info.ip != ip;
                (
                    peer.uuid != rk.uuid || peer.pk != rk.pk || ip_changed,
                    ip_changed,
                )
            }
        };
        let mut req_pk = peer.read().await.reg_pk;
        if req_pk.1.elapsed().as_secs() > 6 {
            req_pk.0 = 0;
        } else if req_pk.0 > 2 {
            return Err(TOO_FREQUENT);
            //return Err(send_rk_res(socket, addr, TOO_FREQUENT).await);
        }
        req_pk.0 += 1;
        req_pk.1 = Instant::now();
        peer.write().await.reg_pk = req_pk;
        if ip_changed {
            let mut lock = IP_CHANGES.lock().await;
            if let Some((tm, ips)) = lock.get_mut(&id) {
                if tm.elapsed().as_secs() > IP_CHANGE_DUR {
                    *tm = Instant::now();
                    ips.clear();
                    ips.insert(ip.clone(), 1);
                } else if let Some(v) = ips.get_mut(&ip) {
                    *v += 1;
                } else {
                    ips.insert(ip.clone(), 1);
                }
            } else {
                lock.insert(
                    id.clone(),
                    (Instant::now(), HashMap::from([(ip.clone(), 1)])),
                );
            }
        }
        if changed || ws {
            // update peer info，解决tcp过程中不更新在线时间的问题
            let result = self.pm.update_pk(id, peer, addr, rk.uuid, rk.pk, ip).await;
            if result != register_pk_response::Result::OK {
                return Err(result);
            }
        }
        Ok(register_pk_response::Result::OK)
        // let mut msg_out = RendezvousMessage::new();
        // msg_out.set_register_pk_response(RegisterPkResponse {
        //     result: register_pk_response::Result::OK.into(),
        //     ..Default::default()
        // });
        // Ok(msg_out)
    }

    #[inline]
    async fn update_addr(&mut self, id: String, socket_addr: SocketAddr) -> bool {
        if crate::api_bridge::configured() {
            if let Some(peer) = self.pm.get(&id).await {
                let (uuid, pk) = {
                    let peer = peer.read().await;
                    (peer.uuid.clone(), peer.pk.clone())
                };
                if !crate::api_bridge::admitted(&id, &uuid, &pk)
                    .await
                    .unwrap_or(false)
                {
                    return true;
                }
            }
        }
        let (request_pk, ip_change) = self.pm.update_registration_addr(&id, socket_addr).await;
        if let Some(old) = ip_change {
            log::info!("IP change of {} from {} to {}", id, old, socket_addr);
        }
        request_pk
        // let mut msg_out = RendezvousMessage::new();
        // msg_out.set_register_peer_response(RegisterPeerResponse {
        //     request_pk,
        //     ..Default::default()
        // });
        // socket.send(&msg_out, socket_addr).await
    }

    #[inline]
    async fn handle_hole_sent(
        &mut self,
        phs: PunchHoleSent,
        addr: SocketAddr,
        socket: Option<&mut FramedSocket>,
    ) -> ResultType<()> {
        // punch hole sent from B, tell A that B is ready to be connected
        let addr_a = try_into_v4(AddrMangle::decode(&phs.socket_addr));
        if !phs.webrtc_sdp_answer.is_empty()
            && !self
                .ice_routes
                .lock()
                .await
                .answer_allowed(&addr_a, try_into_v4(addr))
        {
            return Ok(());
        }
        log::debug!(
            "{} punch hole response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            addr_a,
            addr
        );
        let mut msg_out = RendezvousMessage::new();
        let tcp_response = self.tcp_punch.lock().await.contains_key(&addr_a);
        let mut p = PunchHoleResponse {
            feedback: i32::from(crate::api_bridge::configured() || !jwt::SECRET.is_empty()),
            socket_addr: AddrMangle::encode(addr).into(),
            pk: self.get_pk(&phs.version, phs.id).await,
            relay_server: phs.relay_server.clone(),
            is_udp: socket.is_some() && tcp_response,
            webrtc_sdp_answer: phs.webrtc_sdp_answer,
            upnp_port: phs.upnp_port,
            socket_addr_v6: phs.socket_addr_v6,
            ..Default::default()
        };
        if let Ok(t) = phs.nat_type.enum_value() {
            p.set_nat_type(t);
        }
        msg_out.set_punch_hole_response(p);
        if tcp_response {
            self.send_to_tcp(msg_out, addr_a).await;
        } else if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        }

        Ok(())
    }

    #[inline]
    async fn handle_local_addr(
        &mut self,
        la: LocalAddr,
        addr: SocketAddr,
        socket: Option<&mut FramedSocket>,
    ) -> ResultType<()> {
        // relay local addrs of B to A
        let addr_a = AddrMangle::decode(&la.socket_addr);
        log::debug!(
            "{} local addrs response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            addr_a,
            addr
        );
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            feedback: i32::from(crate::api_bridge::configured() || !jwt::SECRET.is_empty()),
            socket_addr: la.local_addr.clone(),
            pk: self.get_pk(&la.version, la.id).await,
            relay_server: la.relay_server,
            socket_addr_v6: la.socket_addr_v6,
            ..Default::default()
        };
        p.set_is_local(true);
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<(RendezvousMessage, Option<SocketAddr>)> {
        let mut ph = ph;
        if !key.is_empty() && ph.licence_key != key {
            log::warn!(
                "Authentication failed from {} for peer {} - invalid key",
                addr,
                ph.id
            );
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        let policy = match self
            .authorize_connection(&ph.id, &ph.token, &ph.switch_code)
            .await
        {
            Ok(policy) => policy,
            Err(err) => {
                log::warn!("Connection authorization failed: {err}");
                let mut response = RendezvousMessage::new();
                response.set_punch_hole_response(PunchHoleResponse {
                    other_failure:
                        "Connection authorization failed; please login or check server policy"
                            .into(),
                    ..Default::default()
                });
                return Ok((response, None));
            }
        };
        // Enforced hbbr policy must not be bypassed by an SDP declaring full ICE.
        if ALWAYS_USE_RELAY.load(Ordering::SeqCst) {
            ph.webrtc_sdp_offer.clear();
        }
        let session = if ph.webrtc_sdp_offer.is_empty() {
            None
        } else {
            Some(crate::signaling::offer_session(&ph.webrtc_sdp_offer)?)
        };
        let id = ph.id;
        // punch hole request from A, relay to B,
        // check if in same intranet first,
        // fetch local addrs if in same intranet.
        // because punch hole won't work if in the same intranet,
        // all routers will drop such self-connections.
        if let Some(peer) = self.pm.get(&id).await {
            let (elapsed, peer_addr) = {
                let r = peer.read().await;
                (r.last_reg_time.elapsed().as_millis() as i64, r.socket_addr)
            };
            if elapsed >= REG_TIMEOUT {
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_punch_hole_response(PunchHoleResponse {
                    failure: punch_hole_response::Failure::OFFLINE.into(),
                    ..Default::default()
                });
                return Ok((msg_out, None));
            }
            {
                let from_ip = try_into_v4(addr).ip().to_string();
                let to_ip = try_into_v4(peer_addr).ip().to_string();
                let mut requests = PUNCH_REQS.lock().await;
                while requests
                    .front()
                    .is_some_and(|entry| entry.tm.elapsed().as_secs() >= PUNCH_REQ_TTL_SECS)
                {
                    requests.pop_front();
                }
                let duplicate = requests.iter().rev().take(30).any(|entry| {
                    entry.from_ip == from_ip
                        && entry.to_id == id
                        && entry.tm.elapsed().as_secs() < 60
                });
                if !duplicate {
                    if requests.len() >= MAX_PUNCH_REQS {
                        requests.pop_front();
                    }
                    requests.push_back(PunchReqEntry {
                        tm: Instant::now(),
                        from_ip,
                        to_ip,
                        to_id: id.clone(),
                    });
                }
            }
            let mut msg_out = RendezvousMessage::new();
            let peer_is_lan = self.is_lan(peer_addr);
            let is_lan = self.is_lan(addr);
            let mut relay_server = self.get_relay_server(addr.ip(), peer_addr.ip());
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) || (peer_is_lan ^ is_lan) {
                if peer_is_lan {
                    // https://github.com/rustdesk/rustdesk-server/issues/24
                    relay_server = self.inner.local_ip.clone()
                }
                ph.nat_type = NatType::SYMMETRIC.into(); // will force relay
            }
            let same_intranet: bool = !ws
                && (peer_is_lan && is_lan || {
                    match (peer_addr, addr) {
                        (SocketAddr::V4(a), SocketAddr::V4(b)) => a.ip() == b.ip(),
                        (SocketAddr::V6(a), SocketAddr::V6(b)) => a.ip() == b.ip(),
                        _ => false,
                    }
                });
            if let Some(session) = session {
                self.ice_routes.lock().await.insert(
                    try_into_v4(addr),
                    id.clone(),
                    try_into_v4(peer_addr),
                    session,
                )?;
            }
            let socket_addr = AddrMangle::encode(addr).into();
            if same_intranet && ph.webrtc_sdp_offer.is_empty() {
                log::debug!(
                    "Fetch local addr {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_fetch_local_addr(FetchLocalAddr {
                    socket_addr,
                    relay_server,
                    socket_addr_v6: ph.socket_addr_v6,
                    control_permissions: policy.permissions().into(),
                    controlled_context: policy.context().into(),
                    ..Default::default()
                });
            } else {
                log::debug!(
                    "Punch hole {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_punch_hole(PunchHole {
                    socket_addr,
                    nat_type: ph.nat_type,
                    relay_server,
                    udp_port: ph.udp_port,
                    force_relay: ph.force_relay || ALWAYS_USE_RELAY.load(Ordering::SeqCst),
                    upnp_port: ph.upnp_port,
                    socket_addr_v6: ph.socket_addr_v6,
                    control_permissions: policy.permissions().into(),
                    controlled_context: policy.context().into(),
                    webrtc_sdp_offer: ph.webrtc_sdp_offer,
                    ..Default::default()
                });
            }
            //
            Ok((msg_out, Some(peer_addr)))
        } else {
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                ..Default::default()
            });
            Ok((msg_out, None))
        }
    }

    #[inline]
    async fn handle_online_request(
        &mut self,
        stream: &mut FramedStream,
        peers: Vec<String>,
    ) -> ResultType<()> {
        let states = self.peers_online_state(peers).await;

        let mut msg_out = RendezvousMessage::new();
        msg_out.set_online_response(OnlineResponse {
            states: states.into(),
            ..Default::default()
        });
        stream.send(&msg_out).await?;

        Ok(())
    }

    #[inline]
    async fn send_to_tcp(&mut self, msg: RendezvousMessage, addr: SocketAddr) {
        allow_err!(self.send_to_tcp_sync(msg, addr).await);
    }

    #[inline]
    async fn send_to_sink(sink: &mut Option<Sink>, msg: RendezvousMessage) {
        if let Some(sink) = sink.as_mut() {
            sink.send(&msg).await;
        }
    }

    #[inline]
    async fn send_to_tcp_sync(
        &mut self,
        msg: RendezvousMessage,
        addr: SocketAddr,
    ) -> ResultType<()> {
        let addr = try_into_v4(addr);
        let keep = self.ice_routes.lock().await.has(&addr);
        let sink = {
            let mut sinks = self.tcp_punch.lock().await;
            if keep {
                sinks.get(&addr).cloned()
            } else {
                sinks.remove(&addr)
            }
        };
        if let Some(sink) = sink {
            timeout(3000, async { sink.lock().await.send(&msg).await }).await?;
        }
        Ok(())
    }

    async fn send_to_peer(&self, msg: RendezvousMessage, addr: SocketAddr) -> ResultType<()> {
        let sink = self.ws_map.lock().await.get(&try_into_v4(addr)).cloned();
        if let Some(sink) = sink {
            timeout(3000, async { sink.lock().await.send(&msg).await }).await?;
        } else {
            self.tx.send(Data::Msg(msg.into(), addr))?;
        }
        Ok(())
    }

    async fn respond_to_connection(
        &self,
        sink: &mut Option<Sink>,
        msg: RendezvousMessage,
        addr: SocketAddr,
    ) {
        if sink.is_some() {
            Self::send_to_sink(sink, msg).await;
        } else {
            let stored = self.ws_map.lock().await.get(&try_into_v4(addr)).cloned();
            let stored = match stored {
                Some(stored) => Some(stored),
                None => self.tcp_punch.lock().await.get(&try_into_v4(addr)).cloned(),
            };
            if let Some(stored) = stored {
                allow_err!(timeout(3000, async { stored.lock().await.send(&msg).await }).await);
            }
        }
    }

    async fn handle_ice(&mut self, mut ice: IceCandidate, from: SocketAddr) -> ResultType<()> {
        let from = try_into_v4(from);
        let to_peer = !ice.id.is_empty();
        let controller = if to_peer {
            from
        } else {
            try_into_v4(AddrMangle::decode(&ice.socket_addr))
        };
        let target = self.ice_routes.lock().await.candidate(
            from,
            controller,
            &ice.id,
            &ice.session_key,
            &ice.candidate,
        );
        let Some(target) = target else {
            bail!("Invalid or expired ICE route");
        };
        ice.socket_addr = Default::default();
        ice.id.clear();
        let mut msg = RendezvousMessage::new();
        msg.set_ice_candidate(ice);
        if to_peer {
            self.send_to_peer(msg, target).await
        } else {
            self.send_to_tcp_sync(msg, target).await
        }
    }

    #[inline]
    async fn handle_tcp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, ws).await?;
        if let Some(addr) = to_addr {
            self.send_to_peer(msg, addr).await?;
        } else {
            self.send_to_tcp_sync(msg, addr).await?;
        }
        Ok(())
    }

    #[inline]
    async fn handle_udp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
    ) -> ResultType<()> {
        if !ph.webrtc_sdp_offer.is_empty() {
            bail!("WebRTC offers require TCP or WebSocket");
        }
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, false).await?;
        self.tx
            .send(Data::Msg(msg.into(), to_addr.unwrap_or(addr)))?;
        Ok(())
    }

    async fn check_ip_blocker(&self, ip: &str, id: &str) -> bool {
        let mut lock = IP_BLOCKER.lock().await;
        let now = Instant::now();
        if let Some(old) = lock.get_mut(ip) {
            let counter = &mut old.0;
            if counter.1.elapsed().as_secs() > IP_BLOCK_DUR {
                counter.0 = 0;
            } else if counter.0 > 30 {
                return false;
            }
            counter.0 += 1;
            counter.1 = now;

            let counter = &mut old.1;
            let is_new = !counter.0.contains(id);
            if counter.1.elapsed().as_secs() > DAY_SECONDS {
                counter.0.clear();
            } else if counter.0.len() > 300 {
                return !is_new;
            }
            if is_new {
                counter.0.insert(id.to_owned());
            }
            counter.1 = now;
        } else {
            lock.insert(ip.to_owned(), ((0, now), (Default::default(), now)));
        }
        true
    }

    fn parse_relay_servers(&mut self, relay_servers: &str) {
        let rs = get_servers(relay_servers, "relay-servers");
        self.relay_servers0 = Arc::new(rs);
        self.relay_servers = self.relay_servers0.clone();
    }

    fn get_relay_server(&self, _pa: IpAddr, _pb: IpAddr) -> String {
        if self.relay_servers.is_empty() {
            return "".to_owned();
        } else if self.relay_servers.len() == 1 {
            return self.relay_servers[0].clone();
        }
        let i = ROTATION_RELAY_SERVER.fetch_add(1, Ordering::SeqCst) % self.relay_servers.len();
        self.relay_servers[i].clone()
    }

    async fn check_cmd(&self, cmd: &str) -> String {
        use std::fmt::Write as _;

        let mut res = "".to_owned();
        let mut fds = cmd.trim().split(' ');
        match fds.next() {
            Some("h") => {
                res = format!(
                    "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                    "relay-servers(rs) <separated by ,>",
                    "reload-geo(rg)",
                    "ip-blocker(ib) [<ip>|<number>] [-]",
                    "ip-changes(ic) [<id>|<number>] [-]",
                    "punch-requests(pr) [<number>] [-]",
                    "always-use-relay(aur) [Y|N]",
                    "test-geo(tg) <ip1> <ip2>",
                    "must-login(ml) [Y|N]",
                )
            }
            Some("relay-servers" | "rs") => {
                if let Some(rs) = fds.next() {
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    for ip in self.relay_servers.iter() {
                        let _ = writeln!(res, "{ip}");
                    }
                }
            }
            Some("ip-blocker" | "ib") => {
                let mut lock = IP_BLOCKER.lock().await;
                lock.retain(|&_, (a, b)| {
                    a.1.elapsed().as_secs() <= IP_BLOCK_DUR
                        || b.1.elapsed().as_secs() <= DAY_SECONDS
                });
                res = format!("{}\n", lock.len());
                let ip = fds.next();
                let mut start = ip.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if start < 0 {
                    if let Some(ip) = ip {
                        if let Some((a, b)) = lock.get(ip) {
                            let _ = writeln!(
                                res,
                                "{}/{}s {}/{}s",
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                        if fds.next() == Some("-") {
                            lock.remove(ip);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((ip, (a, b))) = x {
                            let _ = writeln!(
                                res,
                                "{}: {}/{}s {}/{}s",
                                ip,
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                    }
                }
            }
            Some("ip-changes" | "ic") => {
                let mut lock = IP_CHANGES.lock().await;
                lock.retain(|&_, v| v.0.elapsed().as_secs() < IP_CHANGE_DUR_X2 && v.1.len() > 1);
                res = format!("{}\n", lock.len());
                let id = fds.next();
                let mut start = id.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if !(0..=10_000_000).contains(&start) {
                    if let Some(id) = id {
                        if let Some((tm, ips)) = lock.get(id) {
                            let _ = writeln!(res, "{}s {:?}", tm.elapsed().as_secs(), ips);
                        }
                        if fds.next() == Some("-") {
                            lock.remove(id);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((id, (tm, ips))) = x {
                            let _ = writeln!(res, "{}: {}s {:?}", id, tm.elapsed().as_secs(), ips,);
                        }
                    }
                }
            }
            Some("punch-requests" | "pr") => {
                let mut requests = PUNCH_REQS.lock().await;
                requests.retain(|entry| entry.tm.elapsed().as_secs() < PUNCH_REQ_TTL_SECS);
                let arg = fds.next();
                if arg == Some("-") {
                    requests.clear();
                } else {
                    let start = arg
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or(0);
                    for entry in requests.iter().skip(start).take(10) {
                        let age = entry.tm.elapsed();
                        let timestamp = std::time::SystemTime::now()
                            .checked_sub(age)
                            .map(chrono::DateTime::<chrono::Utc>::from)
                            .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                            .unwrap_or_default();
                        let _ = writeln!(
                            res,
                            "{} {} -> {}@{}",
                            timestamp, entry.from_ip, entry.to_id, entry.to_ip
                        );
                    }
                }
            }
            Some("always-use-relay" | "aur") => {
                if let Some(rs) = fds.next() {
                    if rs.to_uppercase() == "Y" {
                        ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
                    } else {
                        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
                    }
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    let _ = writeln!(
                        res,
                        "ALWAYS_USE_RELAY: {:?}",
                        ALWAYS_USE_RELAY.load(Ordering::SeqCst)
                    );
                }
            }
            Some("test-geo" | "tg") => {
                if let Some(rs) = fds.next() {
                    if let Ok(a) = rs.parse::<IpAddr>() {
                        if let Some(rs) = fds.next() {
                            if let Ok(b) = rs.parse::<IpAddr>() {
                                res = format!("{:?}", self.get_relay_server(a, b));
                            }
                        } else {
                            res = format!("{:?}", self.get_relay_server(a, a));
                        }
                    }
                }
            }
            Some("must-login" | "ml") => {
                if let Some(rs) = fds.next() {
                    if rs.to_uppercase() == "Y" {
                        MUST_LOGIN.store(true, Ordering::SeqCst);
                    } else {
                        MUST_LOGIN.store(false, Ordering::SeqCst);
                    }
                } else {
                    let _ = writeln!(res, "MUST_LOGIN: {:?}", MUST_LOGIN.load(Ordering::SeqCst));
                }
            }
            Some("registry-v1") => {
                return self.check_registry_cmd(fds.next()).await;
            }
            _ => {}
        }
        res
    }

    async fn check_registry_cmd(&self, payload: Option<&str>) -> String {
        let Some(payload) = payload else {
            return registry_error("INVALID_REQUEST", "Missing registry request");
        };
        let decoded = match base64::decode_config(payload, base64::URL_SAFE_NO_PAD) {
            Ok(decoded) => decoded,
            Err(_) => return registry_error("INVALID_REQUEST", "Invalid registry request"),
        };
        let request = match serde_json::from_slice::<RegistryRequest>(&decoded) {
            Ok(request) => request,
            Err(_) => return registry_error("INVALID_REQUEST", "Invalid registry request"),
        };
        match request.operation.as_str() {
            "list" => {
                let page = request.page.unwrap_or(1);
                let page_size = request.page_size.unwrap_or(50);
                let keyword = request.keyword.unwrap_or_default();
                if page == 0 || page_size == 0 || page_size > 100 {
                    return registry_error("INVALID_PAGE_SIZE", "Invalid pagination");
                }
                if keyword.chars().count() > 100 {
                    return registry_error("INVALID_REQUEST", "Keyword is too long");
                }
                match self.pm.list_registry_peers(page, page_size, &keyword).await {
                    Ok(data) => registry_success(data),
                    Err(err) => {
                        log::error!("Failed to list registry peers: {err}");
                        registry_error("DATABASE_ERROR", "Registry query failed")
                    }
                }
            }
            "detail" => {
                let Some(id) = valid_registry_id(request.id) else {
                    return registry_error("INVALID_REQUEST", "Invalid peer ID");
                };
                match self.pm.registry_peer_detail(&id).await {
                    Ok(Some(data)) => registry_success(data),
                    Ok(None) => registry_error("PEER_NOT_FOUND", "Peer not found"),
                    Err(err) => {
                        log::error!("Failed to query registry peer: {err}");
                        registry_error("DATABASE_ERROR", "Registry query failed")
                    }
                }
            }
            "stats" => match self.pm.registry_stats().await {
                Ok(data) => registry_success(data),
                Err(err) => {
                    log::error!("Failed to query registry stats: {err}");
                    registry_error("DATABASE_ERROR", "Registry query failed")
                }
            },
            "delete" => {
                let Some(id) = valid_registry_id(request.id) else {
                    return registry_error("INVALID_REQUEST", "Invalid peer ID");
                };
                let Some(uuid) = request.uuid.and_then(|value| base64::decode(value).ok()) else {
                    return registry_error("INVALID_REQUEST", "Invalid peer identity");
                };
                let Some(fingerprint) = request.public_key_fingerprint else {
                    return registry_error("INVALID_REQUEST", "Invalid peer identity");
                };
                match self
                    .pm
                    .delete_registry_peer(&id, &uuid, &fingerprint, request.force)
                    .await
                {
                    Ok(()) => registry_success(serde_json::json!({ "id": id })),
                    Err(RegistryDeleteError::NotFound) => {
                        registry_error("PEER_NOT_FOUND", "Peer not found")
                    }
                    Err(RegistryDeleteError::IdentityMismatch) => registry_error(
                        "PEER_IDENTITY_CHANGED",
                        "Peer identity changed; refresh and try again",
                    ),
                    Err(RegistryDeleteError::RecentlyActive) => registry_error(
                        "PEER_RECENTLY_ACTIVE",
                        "Peer registered recently; force is required",
                    ),
                    Err(RegistryDeleteError::Database) => {
                        registry_error("DATABASE_ERROR", "Registry delete failed")
                    }
                }
            }
            _ => registry_error("INVALID_REQUEST", "Unsupported registry operation"),
        }
    }

    async fn handle_listener2(&self, stream: TcpStream, addr: SocketAddr) {
        let mut rs = self.clone();
        let ip = try_into_v4(addr).ip();
        if ip.is_loopback() {
            tokio::spawn(async move {
                let mut stream = stream;
                let mut request = Vec::new();
                let mut chunk = [0_u8; 512];
                loop {
                    let wait_ms = if request.is_empty() { 1000 } else { 100 };
                    match timeout(wait_ms, stream.read(&mut chunk)).await {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => {
                            request.extend_from_slice(&chunk[..n]);
                            if request.len() > MANAGEMENT_REQUEST_LIMIT || request.contains(&b'\n')
                            {
                                break;
                            }
                            let prefix = b"registry-v1 ";
                            if !prefix.starts_with(&request) && !request.starts_with(prefix) {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
                let response = if request.len() > MANAGEMENT_REQUEST_LIMIT {
                    registry_error("REQUEST_TOO_LARGE", "Registry request is too large")
                } else if let Some(newline) = request.iter().position(|byte| *byte == b'\n') {
                    match std::str::from_utf8(&request[..newline]) {
                        Ok(data) => rs.check_cmd(data).await,
                        Err(_) => registry_error("INVALID_REQUEST", "Invalid registry request"),
                    }
                } else {
                    match std::str::from_utf8(&request) {
                        Ok(data) => rs.check_cmd(data).await,
                        Err(_) => String::new(),
                    }
                };
                let response = if response.len() > MANAGEMENT_RESPONSE_LIMIT {
                    registry_error("RESPONSE_TOO_LARGE", "Registry response is too large")
                } else {
                    response
                };
                if stream.write_all(response.as_bytes()).await.is_ok() {
                    stream.shutdown().await.ok();
                }
            });
            return;
        }
        let stream = FramedStream::from(stream, addr);
        tokio::spawn(async move {
            let mut stream = stream;
            if let Some(Ok(bytes)) = stream.next_timeout(30_000).await {
                if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                    match msg_in.union {
                        Some(rendezvous_message::Union::TestNatRequest(_)) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_test_nat_response(TestNatResponse {
                                port: addr.port() as _,
                                ..Default::default()
                            });
                            stream.send(&msg_out).await.ok();
                        }
                        Some(rendezvous_message::Union::OnlineRequest(or)) => {
                            allow_err!(rs.handle_online_request(&mut stream, or.peers).await);
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    async fn handle_listener(&self, stream: TcpStream, addr: SocketAddr, key: &str, ws: bool) {
        let Ok(permit) = SIGNALING_SLOTS.clone().try_acquire_owned() else {
            return;
        };
        log::debug!("Tcp connection from {:?}, ws: {}", addr, ws);
        let mut rs = self.clone();
        let key = key.to_owned();
        tokio::spawn(async move {
            let _permit = permit;
            allow_err!(rs.handle_listener_inner(stream, addr, &key, ws).await);
        });
    }

    #[inline]
    async fn handle_listener_inner(
        &mut self,
        stream: TcpStream,
        mut addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let mut sink;
        let handshake = Handshake::new();
        let mut receiver = None;
        if ws {
            use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
            #[allow(clippy::result_large_err)] // tungstenite callback fixes this error type.
            let callback = |req: &Request, response: Response| {
                let headers = req.headers();
                let real_ip = headers
                    .get("X-Real-IP")
                    .or_else(|| headers.get("X-Forwarded-For"))
                    .and_then(|header_value| header_value.to_str().ok());
                if let Some(ip) = real_ip.filter(|_| addr.ip().is_loopback()) {
                    if ip.contains('.') {
                        addr = format!("{ip}:{}", addr.port()).parse().unwrap_or(addr);
                    } else {
                        addr = format!("[{ip}]:{}", addr.port()).parse().unwrap_or(addr);
                    }
                }
                Ok(response)
            };
            let config = tungstenite::protocol::WebSocketConfig {
                max_message_size: Some(MAX_SIGNAL_BYTES),
                max_frame_size: Some(MAX_SIGNAL_BYTES),
                ..Default::default()
            };
            let ws_stream = timeout(
                5000,
                tokio_tungstenite::accept_hdr_async_with_config(stream, callback, Some(config)),
            )
            .await??;
            let (a, mut b) = ws_stream.split();
            sink = Some(Sink::Wss(SafeWsSink {
                sink: a,
                encrypt: None,
            }));
            while let Ok(Some(Ok(msg))) = timeout(30_000, b.next()).await {
                if let tungstenite::Message::Binary(bytes) = msg {
                    if !self.handle_tcp(&bytes, &mut sink, addr, key, ws).await {
                        break;
                    }
                }
            }
        } else {
            let mut codec = BytesCodec::new();
            codec.set_max_packet_length(MAX_SIGNAL_BYTES);
            let (a, mut b) = Framed::new(stream, codec).split();
            sink = Some(Sink::Tss(SafeTcpStreamSink {
                sink: a,
                encrypt: None,
            }));
            // Avoid key exchange if answering on nat helper port
            if !key.is_empty() {
                if let Some(sk) = &self.inner.sk {
                    let mut offer = RendezvousMessage::new();
                    offer.set_key_exchange(handshake.offer(sk)?);
                    Self::send_to_sink(&mut sink, offer).await;
                }
            }
            while let Ok(Some(Ok(mut bytes))) = timeout(30_000, b.next()).await {
                match prepare_frame(
                    &mut bytes,
                    &mut sink,
                    &mut receiver,
                    &handshake,
                    !key.is_empty(),
                ) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(err) => {
                        log::debug!("Invalid signaling frame from {addr}: {err}");
                        break;
                    }
                }
                if let Some(rendezvous_message::Union::Hc(hc)) =
                    RendezvousMessage::parse_from_bytes(&bytes)?.union
                {
                    if sink.is_none() {
                        break;
                    }
                    let authorized = if crate::api_bridge::configured() {
                        crate::api_bridge::authorize("", &hc.token, "", true, &[], &[])
                            .await
                            .is_ok()
                    } else {
                        jwt::verify_token(&hc.token).is_ok()
                    };
                    if !authorized {
                        break;
                    }
                    let mut reply = RendezvousMessage::new();
                    reply.set_register_pk_response(RegisterPkResponse {
                        keep_alive: 20,
                        ..Default::default()
                    });
                    Self::send_to_sink(&mut sink, reply).await;
                    loop {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        let valid = if crate::api_bridge::configured() {
                            crate::api_bridge::authorize("", &hc.token, "", true, &[], &[])
                                .await
                                .is_ok()
                        } else {
                            jwt::verify_token(&hc.token).is_ok()
                        };
                        if !valid {
                            break;
                        }
                        Self::send_to_sink(&mut sink, RendezvousMessage::new()).await;
                        match timeout(15_000, b.next()).await {
                            Ok(Some(Ok(mut heartbeat))) => {
                                if let Some(cipher) = receiver.as_mut() {
                                    cipher.dec(&mut heartbeat)?;
                                }
                                if !heartbeat.is_empty() {
                                    break;
                                }
                            }
                            _ => break,
                        }
                    }
                    break;
                }
                if !self.handle_tcp(&bytes, &mut sink, addr, key, ws).await {
                    break;
                }
            }
        }
        if sink.is_none() {
            self.ice_routes.lock().await.remove(&try_into_v4(addr));
            self.tcp_punch.lock().await.remove(&try_into_v4(addr));
            self.ws_map.lock().await.remove(&try_into_v4(addr));
        }
        log::debug!("Tcp connection from {:?} closed", addr);
        Ok(())
    }

    #[inline]
    async fn get_pk(&mut self, version: &str, id: String) -> Bytes {
        if version.is_empty() {
            return Bytes::new();
        }
        if let Some(sk) = self.inner.sk.as_ref() {
            match self.pm.get(&id).await {
                Some(peer) => {
                    let pk = peer.read().await.pk.clone();
                    sign::sign(
                        &hbb_common::message_proto::IdPk {
                            id,
                            pk,
                            ..Default::default()
                        }
                        .write_to_bytes()
                        .unwrap_or_default(),
                        sk,
                    )
                    .into()
                }
                _ => Bytes::new(),
            }
        } else {
            Bytes::new()
        }
    }

    #[inline]
    fn get_server_sk(key: &str) -> (String, Option<sign::SecretKey>) {
        let mut out_sk = None;
        let mut key = key.to_owned();
        if let Ok(sk) = base64::decode(&key) {
            if sk.len() == sign::SECRETKEYBYTES {
                log::info!("The key is a crypto private key");
                key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
                let mut tmp = [0u8; sign::SECRETKEYBYTES];
                tmp[..].copy_from_slice(&sk);
                out_sk = Some(sign::SecretKey(tmp));
            }
        }

        if key.is_empty() || key == "-" || key == "_" {
            let (pk, sk) = crate::common::gen_sk(0);
            out_sk = sk;
            if !key.is_empty() {
                key = pk;
            }
        }

        if !key.is_empty() {
            log::info!("Key: {}", key);
        }
        (key, out_sk)
    }

    #[inline]
    fn is_lan(&self, addr: SocketAddr) -> bool {
        if let Some(network) = &self.inner.mask {
            match addr {
                SocketAddr::V4(v4_socket_addr) => {
                    return network.contains(*v4_socket_addr.ip());
                }

                SocketAddr::V6(v6_socket_addr) => {
                    if let Some(v4_addr) = v6_socket_addr.ip().to_ipv4() {
                        return network.contains(v4_addr);
                    }
                }
            }
        }
        false
    }
}

async fn check_relay_servers(rs0: Arc<RelayServers>, tx: Sender) {
    let mut futs = Vec::new();
    let rs = Arc::new(Mutex::new(Vec::new()));
    for x in rs0.iter() {
        let mut host = x.to_owned();
        if !host.contains(':') {
            host = format!("{}:{}", host, config::RELAY_PORT);
        }
        let rs = rs.clone();
        let x = x.clone();
        futs.push(tokio::spawn(async move {
            if FramedStream::new(&host, None, CHECK_RELAY_TIMEOUT)
                .await
                .is_ok()
            {
                rs.lock().await.push(x);
            }
        }));
    }
    join_all(futs).await;
    log::debug!("check_relay_servers");
    let rs = std::mem::take(&mut *rs.lock().await);
    if !rs.is_empty() {
        tx.send(Data::RelayServers(rs)).ok();
    }
}

// temp solution to solve udp socket failure
async fn test_hbbs(addr: SocketAddr) -> ResultType<()> {
    let mut addr = addr;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        });
    }

    let mut socket = FramedSocket::new(config::Config::get_any_listen_addr(addr.is_ipv4())).await?;
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_peer(RegisterPeer {
        id: "(:test_hbbs:)".to_owned(),
        ..Default::default()
    });
    let mut last_time_recv = Instant::now();

    let mut timer = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
          _ = timer.tick() => {
              if last_time_recv.elapsed().as_secs() > 12 {
                  bail!("Timeout of test_hbbs");
              }
              socket.send(&msg_out, addr).await?;
          }
          Some(Ok((bytes, _))) = socket.next() => {
              if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                 log::trace!("Recv {:?} of test_hbbs", msg_in);
                 last_time_recv = Instant::now();
              }
          }
        }
    }
}

async fn create_udp_listener(port: i32, rmem: usize) -> ResultType<FramedSocket> {
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port as _);
    if let Ok(s) = FramedSocket::new_reuse(&addr, true, rmem).await {
        log::debug!("listen on udp {:?}", s.local_addr());
        return Ok(s);
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port as _);
    let s = FramedSocket::new_reuse(&addr, true, rmem).await?;
    log::debug!("listen on udp {:?}", s.local_addr());
    Ok(s)
}

#[inline]
async fn create_tcp_listener(port: i32) -> ResultType<TcpListener> {
    let s = listen_any(port as _).await?;
    log::debug!("listen on tcp {:?}", s.local_addr());
    Ok(s)
}

fn prepare_frame(
    bytes: &mut BytesMut,
    sink: &mut Option<Sink>,
    receiver: &mut Option<Encrypt>,
    handshake: &Handshake,
    offered: bool,
) -> ResultType<bool> {
    if let Some(cipher) = receiver.as_mut() {
        cipher.dec(bytes)?;
    }
    let msg = RendezvousMessage::parse_from_bytes(bytes)?;
    if let Some(rendezvous_message::Union::KeyExchange(response)) = msg.union.as_ref() {
        if !offered || receiver.is_some() {
            bail!("Unexpected key exchange");
        }
        let (send, recv) = handshake.accept(response)?;
        match sink.as_mut() {
            Some(Sink::Tss(s)) => s.encrypt = Some(send),
            Some(Sink::Wss(s)) => s.encrypt = Some(send),
            None => bail!("Key exchange after connection handoff"),
        }
        *receiver = Some(recv);
        return Ok(true);
    }
    let needs_encryption = match msg.union.as_ref() {
        Some(rendezvous_message::Union::HttpProxyRequest(_))
        | Some(rendezvous_message::Union::Hc(_)) => true,
        Some(rendezvous_message::Union::PunchHoleRequest(ph)) => !ph.webrtc_sdp_offer.is_empty(),
        Some(rendezvous_message::Union::PunchHoleSent(ph)) => !ph.webrtc_sdp_answer.is_empty(),
        Some(rendezvous_message::Union::RelayResponse(rr)) => !rr.webrtc_sdp_answer.is_empty(),
        Some(rendezvous_message::Union::IceCandidate(_)) => true,
        _ => false,
    };
    if needs_encryption && receiver.is_none() {
        bail!("This request requires encrypted TCP signaling");
    }
    Ok(false)
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;
    use crate::handshake::tests::client_response;
    use hbb_common::rendezvous_proto as legacy;

    async fn server() -> (
        RendezvousServer,
        Receiver,
        sign::PublicKey,
        std::path::PathBuf,
    ) {
        let path =
            std::env::temp_dir().join(format!("hbbs-signaling-{}.sqlite3", uuid::Uuid::new_v4()));
        let db = crate::database::Database::new(path.to_str().unwrap())
            .await
            .unwrap();
        db.insert_peer("peer123", b"uuid", &[7; 32], "{}")
            .await
            .unwrap();
        let pm = PeerMap::with_database(db);
        assert!(pm.get("peer123").await.is_some());
        let (tx, rx) = mpsc::unbounded_channel();
        let (pk, sk) = sign::gen_keypair();
        let mut server = RendezvousServer {
            tcp_punch: Default::default(),
            ice_routes: Default::default(),
            pm,
            tx,
            relay_servers: Arc::new(vec!["relay.example".into()]),
            relay_servers0: Default::default(),
            rendezvous_servers: Default::default(),
            inner: Arc::new(Inner {
                serial: 0,
                version: String::new(),
                software_url: String::new(),
                mask: None,
                local_ip: String::new(),
                sk: Some(sk),
            }),
            ws_map: Default::default(),
        };
        assert!(
            !server
                .update_addr("peer123".into(), "127.0.0.1:21116".parse().unwrap())
                .await
        );
        (server, rx, pk, path)
    }

    async fn connect(
        server: &RendezvousServer,
        signing_pk: &sign::PublicKey,
        version: u32,
    ) -> (
        Framed<TcpStream, BytesCodec>,
        Encrypt,
        Encrypt,
        tokio::task::JoinHandle<ResultType<()>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (accepted, addr) = listener.accept().await.unwrap();
        let mut server = server.clone();
        let key = base64::encode(signing_pk.0);
        let task = tokio::spawn(async move {
            server
                .handle_listener_inner(accepted, addr, &key, false)
                .await
        });
        let mut stream = Framed::new(stream, BytesCodec::new());
        let bytes = timeout(2000, stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let offer = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
        let (response, tx, rx) = client_response(offer.key_exchange(), signing_pk, version);
        let mut msg = RendezvousMessage::new();
        msg.set_key_exchange(response);
        stream
            .send(msg.write_to_bytes().unwrap().into())
            .await
            .unwrap();
        (stream, tx, rx, task)
    }

    async fn receive(
        stream: &mut Framed<TcpStream, BytesCodec>,
        cipher: &mut Encrypt,
    ) -> RendezvousMessage {
        let mut bytes = timeout(2000, stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        cipher.dec(&mut bytes).unwrap();
        RendezvousMessage::parse_from_bytes(&bytes).unwrap()
    }

    #[test]
    fn api_admission_does_not_block_udp_and_rename_uses_registered_key() {
        // Environment configuration is process-wide: isolate this test from parallel legacy tests.
        const CHILD: &str = "HBBS_API_REVIEW_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "rendezvous_server::compatibility_tests::api_admission_does_not_block_udp_and_rename_uses_registered_key", "--nocapture"])
                .env(CHILD, "1")
                .env_remove("RUSTDESK_API_INTERNAL_URL")
                .output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            use axum::{routing::post, Json, Router};
            let (mut server, mut deliveries, _, path) = server().await;
            let started = Arc::new(tokio::sync::Notify::new());
            let gate = Arc::new(Semaphore::new(0));
            let notify = started.clone();
            let wait = gate.clone();
            let app = Router::new().route("/api/internal/client/admission", post(move |Json(body): Json<serde_json::Value>| {
                let notify = notify.clone(); let wait = wait.clone();
                async move {
                    notify.notify_one();
                    wait.acquire().await.unwrap().forget();
                    Json(serde_json::json!({"allowed": body["pk"] == base64::encode([7;32]) && body["uuid"] == base64::encode(b"uuid")}))
                }
            })).route("/api/internal/client/authorize", post(|Json(body): Json<serde_json::Value>| async move {
                Json(serde_json::json!({"allowed": body["pk"] == base64::encode([7;32]) && body["uuid"] == base64::encode(b"uuid"), "permissions":1,"conn_audit_ref":"test-ref"}))
            }));
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            std::env::set_var("RUSTDESK_API_INTERNAL_URL",format!("http://{}",listener.local_addr().unwrap()));
            std::env::set_var("RUSTDESK_API_CLIENT_COMPATIBILITY_INTERNAL_SECRET","s".repeat(32));
            let http = tokio::spawn(axum::Server::from_tcp(listener).unwrap().serve(app.into_make_service()));
            let mut udp = create_udp_listener(0,0).await.unwrap();
            let mut request = RendezvousMessage::new();
            request.set_register_peer(RegisterPeer { id:"peer123".into(),..Default::default() });
            let bytes = BytesMut::from(request.write_to_bytes().unwrap().as_slice());
            timeout(500,server.handle_udp(&bytes,"127.0.0.1:21116".parse().unwrap(),&mut udp,"")).await.unwrap().unwrap();
            timeout(2000,started.notified()).await.unwrap();
            assert!(deliveries.try_recv().is_err(),"API request should still be waiting");
            gate.add_permits(10);
            let Data::Msg(reply,_) = timeout(2000,deliveries.recv()).await.unwrap().unwrap() else { panic!("expected registration response") };
            assert!(!reply.register_peer_response().request_pk);
            let policy = server.authorize_connection("peer123","","switch").await.unwrap();
            assert_eq!(policy.permissions,1);
            for _ in 0..2 {
                assert_eq!(server.handle_register_pk(RegisterPk {
                    old_id:"peer123".into(),id:"renamed123".into(),uuid:Bytes::from_static(b"uuid"),..Default::default()
                },"127.0.0.1:21116".parse().unwrap(),false).await.unwrap(),register_pk_response::Result::OK);
            }
            assert!(server.pm.get("peer123").await.is_none());
            assert_eq!(server.pm.get("renamed123").await.unwrap().read().await.pk.as_ref(),&[7;32]);
            http.abort();
            drop(server);
            std::fs::remove_file(path).unwrap();
        });
    }

    #[tokio::test]
    async fn relay_preserves_legacy_empty_key_and_discards_controller_policy() {
        let (server, mut deliveries, pk, path) = server().await;
        for version in [0, 1] {
            let (mut stream, mut tx, mut rx, task) = connect(&server, &pk, version).await;
            let mut message = RendezvousMessage::new();
            message.set_request_relay(RequestRelay {
                id: "peer123".into(),
                control_permissions: Some(ControlPermissions {
                    permissions: 2,
                    ..Default::default()
                })
                .into(),
                controlled_context: Some(ControlledContext {
                    conn_audit_ref: "forged".into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            });
            stream
                .send(tx.enc(&message.write_to_bytes().unwrap()).into())
                .await
                .unwrap();
            let Data::Msg(forwarded, _) = timeout(2000, deliveries.recv()).await.unwrap().unwrap()
            else {
                panic!("expected relay request")
            };
            assert!(forwarded.has_request_relay());
            assert!(forwarded.request_relay().control_permissions.is_none());
            assert!(forwarded.request_relay().controlled_context.is_none());
            message.mut_request_relay().licence_key = "wrong".into();
            stream
                .send(tx.enc(&message.write_to_bytes().unwrap()).into())
                .await
                .unwrap();
            let reply = receive(&mut stream, &mut rx).await;
            assert!(!reply.relay_response().refuse_reason.is_empty());
            task.await.unwrap().unwrap();
        }
        drop(server);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn encrypted_offer_answer_and_trickle_survive_sink_handoff() {
        let (mut server, mut deliveries, pk, path) = server().await;
        for version in [0, 1] {
            let (mut controller, mut tx, mut rx, task) = connect(&server, &pk, version).await;
            let controller_addr = controller.get_ref().local_addr().unwrap();
            let mut msg = RendezvousMessage::new();
            msg.set_punch_hole_request(PunchHoleRequest {
                id: "peer123".into(),
                licence_key: base64::encode(pk.0),
                version: "1.5.0".into(),
                webrtc_sdp_offer: format!(
                    "webrtc://{}",
                    base64::encode(
                        r#"{"type":"offer","sdp":"v=0\r\na=fingerprint:sha-256 AA:BB\r\n"}"#
                    )
                ),
                ..Default::default()
            });
            controller
                .send(tx.enc(&msg.write_to_bytes().unwrap()).into())
                .await
                .unwrap();
            let Data::Msg(offer, _) = timeout(2000, deliveries.recv()).await.unwrap().unwrap()
            else {
                panic!("Expected offer");
            };
            assert!(!offer.punch_hole().webrtc_sdp_offer.is_empty());
            assert_eq!(
                AddrMangle::decode(&offer.punch_hole().socket_addr),
                controller_addr
            );
            let (mut answerer, mut answer_tx, _, answer_task) =
                connect(&server, &pk, version).await;
            msg.set_punch_hole_sent(PunchHoleSent {
                socket_addr: AddrMangle::encode(controller_addr).into(),
                id: "peer123".into(),
                version: "1.5.0".into(),
                webrtc_sdp_answer: "webrtc://answer".into(),
                ..Default::default()
            });
            answerer
                .send(answer_tx.enc(&msg.write_to_bytes().unwrap()).into())
                .await
                .unwrap();
            let answer = receive(&mut controller, &mut rx).await;
            assert_eq!(
                answer.punch_hole_response().webrtc_sdp_answer,
                "webrtc://answer"
            );
            timeout(2000, answer_task).await.unwrap().unwrap().unwrap();
            let (mut ice_sender, mut ice_tx, _, ice_task) = connect(&server, &pk, version).await;
            for candidate in ["first", "second"] {
                msg.set_ice_candidate(IceCandidate {
                    id: "peer123".into(),
                    session_key: "sha-256 AA:BB".into(),
                    candidate: candidate.into(),
                    ..Default::default()
                });
                controller
                    .send(tx.enc(&msg.write_to_bytes().unwrap()).into())
                    .await
                    .unwrap();
                let Data::Msg(delivery, _) =
                    timeout(2000, deliveries.recv()).await.unwrap().unwrap()
                else {
                    panic!("Expected candidate");
                };
                assert_eq!(delivery.ice_candidate().candidate, candidate);
                msg.set_ice_candidate(IceCandidate {
                    socket_addr: AddrMangle::encode(controller_addr).into(),
                    session_key: "sha-256 AA:BB".into(),
                    candidate: candidate.into(),
                    ..Default::default()
                });
                ice_sender
                    .send(ice_tx.enc(&msg.write_to_bytes().unwrap()).into())
                    .await
                    .unwrap();
                assert_eq!(
                    receive(&mut controller, &mut rx)
                        .await
                        .ice_candidate()
                        .candidate,
                    candidate
                );
            }
            // With UDP punching enabled, the answer arrives on hbbs UDP but must go
            // back to the controller's encrypted TCP stream, not its TCP port over UDP.
            let mut udp = FramedSocket::new("127.0.0.1:0").await.unwrap();
            server
                .handle_hole_sent(
                    PunchHoleSent {
                        socket_addr: AddrMangle::encode(controller_addr).into(),
                        id: "peer123".into(),
                        version: "1.5.0".into(),
                        webrtc_sdp_answer: "webrtc://udp-answer".into(),
                        ..Default::default()
                    },
                    "127.0.0.1:21116".parse().unwrap(),
                    Some(&mut udp),
                )
                .await
                .unwrap();
            let answer = receive(&mut controller, &mut rx).await;
            assert!(answer.punch_hole_response().is_udp);
            assert_eq!(
                answer.punch_hole_response().webrtc_sdp_answer,
                "webrtc://udp-answer"
            );
            // A response without an SDP still reaches legacy fallback consumers.
            server
                .handle_hole_sent(
                    PunchHoleSent {
                        socket_addr: AddrMangle::encode(controller_addr).into(),
                        id: "peer123".into(),
                        version: "1.4.9".into(),
                        ..Default::default()
                    },
                    "127.0.0.1:21116".parse().unwrap(),
                    None,
                )
                .await
                .unwrap();
            let fallback = receive(&mut controller, &mut rx).await;
            let legacy =
                legacy::RendezvousMessage::parse_from_bytes(&fallback.write_to_bytes().unwrap())
                    .unwrap();
            assert!(!legacy.punch_hole_response().pk.is_empty());
            drop(controller);
            timeout(2000, task).await.unwrap().unwrap().unwrap();
            assert!(!server.ice_routes.lock().await.has(&controller_addr));
            assert!(!server.tcp_punch.lock().await.contains_key(&controller_addr));
            drop(ice_sender);
            timeout(2000, ice_task).await.unwrap().unwrap().unwrap();
        }
        drop(server);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn old_client_keeps_lan_path_and_invalid_key_creates_no_route() {
        let (mut server, _, pk, path) = server().await;
        let mut legacy = legacy::RendezvousMessage::new();
        legacy.set_punch_hole_request(legacy::PunchHoleRequest {
            id: "peer123".into(),
            licence_key: base64::encode(pk.0),
            version: "1.4.9".into(),
            ..Default::default()
        });
        let request =
            RendezvousMessage::parse_from_bytes(&legacy.write_to_bytes().unwrap()).unwrap();
        let addr = "127.0.0.1:12345".parse().unwrap();
        let (response, target) = server
            .handle_punch_hole_request(
                addr,
                request.punch_hole_request().clone(),
                &base64::encode(pk.0),
                false,
            )
            .await
            .unwrap();
        assert!(target.is_some());
        assert!(
            legacy::RendezvousMessage::parse_from_bytes(&response.write_to_bytes().unwrap())
                .unwrap()
                .has_fetch_local_addr()
        );
        assert!(!server.ice_routes.lock().await.has(&addr));
        let mut request = request.punch_hole_request().clone();
        request.licence_key.clear();
        let (response, target) = server
            .handle_punch_hole_request(addr, request, &base64::encode(pk.0), false)
            .await
            .unwrap();
        assert!(target.is_none());
        assert_eq!(
            response.punch_hole_response().failure.enum_value().unwrap(),
            punch_hole_response::Failure::LICENSE_MISMATCH
        );
        drop(server);
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn ipv6_addresses_survive_lan_and_wan_rendezvous() {
        let (mut server, mut deliveries, pk, path) = server().await;
        let controller_v6 = "[2001:db8:1::10]:45678".parse().unwrap();
        let peer_v6 = "[2001:db8:2::20]:56789".parse().unwrap();
        let local_v4 = "192.168.1.20:34567".parse().unwrap();
        // v0 is the old client's handshake; v1 is the 1.5.0 client's handshake.
        // Also cover peers which provide no IPv6 address at all.
        for version in [0, 1] {
            for with_ipv6 in [false, true] {
                let sent_v6: Bytes = if with_ipv6 {
                    AddrMangle::encode(controller_v6).into()
                } else {
                    Bytes::new()
                };
                let reply_v6: Bytes = if with_ipv6 {
                    AddrMangle::encode(peer_v6).into()
                } else {
                    Bytes::new()
                };
                for same_lan in [true, false] {
                    let registered = if same_lan {
                        "127.0.0.1:21116"
                    } else {
                        "127.0.0.2:21116"
                    }
                    .parse()
                    .unwrap();
                    assert!(!server.update_addr("peer123".into(), registered).await);
                    let (mut controller, mut tx, mut rx, task) =
                        connect(&server, &pk, version).await;
                    let controller_addr = controller.get_ref().local_addr().unwrap();
                    let mut request = RendezvousMessage::new();
                    request.set_punch_hole_request(PunchHoleRequest {
                        id: "peer123".into(),
                        licence_key: base64::encode(pk.0),
                        version: "1.4.9".into(),
                        socket_addr_v6: sent_v6.clone(),
                        ..Default::default()
                    });
                    controller
                        .send(tx.enc(&request.write_to_bytes().unwrap()).into())
                        .await
                        .unwrap();
                    let Data::Msg(forwarded, target) =
                        timeout(2000, deliveries.recv()).await.unwrap().unwrap()
                    else {
                        panic!("Expected rendezvous request");
                    };
                    assert_eq!(target, registered);
                    let forwarded = legacy::RendezvousMessage::parse_from_bytes(
                        &forwarded.write_to_bytes().unwrap(),
                    )
                    .unwrap();
                    if same_lan {
                        assert!(forwarded.has_fetch_local_addr());
                        assert_eq!(forwarded.fetch_local_addr().socket_addr_v6, sent_v6);
                        server
                            .handle_local_addr(
                                LocalAddr {
                                    socket_addr: AddrMangle::encode(controller_addr).into(),
                                    local_addr: AddrMangle::encode(local_v4).into(),
                                    socket_addr_v6: reply_v6.clone(),
                                    id: "peer123".into(),
                                    version: "1.4.9".into(),
                                    relay_server: "relay.example".into(),
                                    ..Default::default()
                                },
                                registered,
                                None,
                            )
                            .await
                            .unwrap();
                    } else {
                        assert!(forwarded.has_punch_hole());
                        assert_eq!(forwarded.punch_hole().socket_addr_v6, sent_v6);
                        server
                            .handle_hole_sent(
                                PunchHoleSent {
                                    socket_addr: AddrMangle::encode(controller_addr).into(),
                                    socket_addr_v6: reply_v6.clone(),
                                    id: "peer123".into(),
                                    version: "1.4.9".into(),
                                    relay_server: "relay.example".into(),
                                    ..Default::default()
                                },
                                registered,
                                None,
                            )
                            .await
                            .unwrap();
                    }
                    let response = receive(&mut controller, &mut rx).await;
                    let response = legacy::RendezvousMessage::parse_from_bytes(
                        &response.write_to_bytes().unwrap(),
                    )
                    .unwrap();
                    let response = response.punch_hole_response();
                    assert_eq!(response.socket_addr_v6, reply_v6);
                    if with_ipv6 {
                        assert_eq!(AddrMangle::decode(&response.socket_addr_v6), peer_v6);
                    }
                    assert_eq!(
                        AddrMangle::decode(&response.socket_addr),
                        if same_lan { local_v4 } else { registered }
                    );
                    assert_eq!(response.is_local(), same_lan);
                    assert_eq!(response.relay_server, "relay.example");
                    assert!(!response.pk.is_empty());
                    drop(controller);
                    timeout(2000, task).await.unwrap().unwrap().unwrap();
                }
            }
        }
        drop(server);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn websocket_registration_stays_available_for_offers_candidates_and_heartbeats() {
        let (server, _, pk, path) = server().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let mut rs = server.clone();
        let key = base64::encode(pk.0);
        let peer_task = tokio::spawn(async move {
            let (stream, addr) = listener.accept().await.unwrap();
            rs.handle_listener_inner(stream, addr, &key, true).await
        });
        let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
        let mut msg = RendezvousMessage::new();
        msg.set_register_pk(RegisterPk {
            id: "peer123".into(),
            uuid: Bytes::from_static(b"uuid"),
            pk: vec![7; 32].into(),
            ..Default::default()
        });
        ws.send(tungstenite::Message::Binary(msg.write_to_bytes().unwrap()))
            .await
            .unwrap();
        let reply = timeout(2000, ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data();
        assert_eq!(
            RendezvousMessage::parse_from_bytes(&reply)
                .unwrap()
                .register_pk_response()
                .result
                .enum_value()
                .unwrap(),
            register_pk_response::Result::OK
        );
        let (mut controller, mut tx, _, task) = connect(&server, &pk, 1).await;
        msg.set_punch_hole_request(PunchHoleRequest {
            id: "peer123".into(),
            licence_key: base64::encode(pk.0),
            version: "1.5.0".into(),
            webrtc_sdp_offer: format!(
                "webrtc://{}",
                base64::encode(r#"{"type":"offer","sdp":"a=fingerprint:sha-256 CC:DD\r\n"}"#)
            ),
            ..Default::default()
        });
        controller
            .send(tx.enc(&msg.write_to_bytes().unwrap()).into())
            .await
            .unwrap();
        let reply = timeout(2000, ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data();
        assert!(RendezvousMessage::parse_from_bytes(&reply)
            .unwrap()
            .has_punch_hole());
        msg.set_ice_candidate(IceCandidate {
            id: "peer123".into(),
            session_key: "sha-256 CC:DD".into(),
            candidate: "candidate".into(),
            ..Default::default()
        });
        controller
            .send(tx.enc(&msg.write_to_bytes().unwrap()).into())
            .await
            .unwrap();
        let reply = timeout(2000, ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data();
        assert!(RendezvousMessage::parse_from_bytes(&reply)
            .unwrap()
            .has_ice_candidate());
        for _ in 0..2 {
            msg.set_register_peer(RegisterPeer {
                id: "peer123".into(),
                ..Default::default()
            });
            ws.send(tungstenite::Message::Binary(msg.write_to_bytes().unwrap()))
                .await
                .unwrap();
            let reply = timeout(2000, ws.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .into_data();
            assert!(RendezvousMessage::parse_from_bytes(&reply)
                .unwrap()
                .has_register_peer_response());
        }
        ws.close(None).await.unwrap();
        timeout(2000, peer_task).await.unwrap().unwrap().unwrap();
        assert!(server.ws_map.lock().await.is_empty());
        drop(controller);
        timeout(2000, task).await.unwrap().unwrap().unwrap();
        drop(server);
        std::fs::remove_file(path).unwrap();
    }
}
