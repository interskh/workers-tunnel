use crate::proxy::{parse_early_data, parse_socks5_config, parse_user_id, run_tunnel};
use crate::websocket::WebSocketStream;
use worker::*;

// MVP: sing-mux + xtaci/smux server-side multiplexing.
// Triggered when the VLESS handshake's destination is sp.mux.sing-box.arpa:444.
// See claudedocs/smux-plan.md for the full design.

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    let uuid_str = env.var("USER_ID")?.to_string();

    let is_websocket = req
        .headers()
        .get("Upgrade")?
        .map(|up| up == "websocket")
        .unwrap_or(false);

    if !is_websocket {
        // Token-gated FlClash subscription endpoint: serves YAML from KV.
        // Kept token separate from USER_ID so URL leaks don't compromise VLESS.
        if req.path() == "/sub" {
            let expected = env
                .var("SUB_TOKEN")
                .map(|v| v.to_string())
                .unwrap_or_default();
            let url = req.url()?;
            let provided = url
                .query_pairs()
                .find(|(k, _)| k.as_ref() == "token")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
            if expected.is_empty() || provided != expected {
                return Response::error("Forbidden", 403);
            }
            let yaml = env
                .kv("CONFIG")?
                .get("flclash")
                .text()
                .await?
                .unwrap_or_default();
            if yaml.is_empty() {
                return Response::error("Config not in KV — run publish.sh", 404);
            }
            let headers = Headers::new();
            headers.set("Content-Type", "text/yaml; charset=utf-8")?;
            return Ok(Response::ok(yaml)?.with_headers(headers));
        }

        let show_uri: bool = env.var("SHOW_URI")?.to_string().parse().unwrap_or(false);
        if show_uri && req.path().contains(uuid_str.as_str()) {
            let host_str = req.url()?.host_str().unwrap_or_default().to_string();
            let vless_uri = format!(
                "vless://{uuid}@{host}:443?encryption=none&security=tls&sni={host}&fp=chrome&type=ws&host={host}&path=ws#workers-tunnel",
                uuid = uuid_str,
                host = host_str
            );
            return Response::ok(vless_uri);
        }

        let fallback_site = env
            .var("FALLBACK_SITE")
            .map(|v| v.to_string())
            .unwrap_or_default();
        if !fallback_site.is_empty() {
            return Fetch::Url(Url::parse(&fallback_site)?).send().await;
        }

        return Response::ok("ok");
    }

    let user_id = parse_user_id(&uuid_str);

    let proxy_ip: Vec<String> = env
        .var("PROXY_IP")?
        .to_string()
        .split_ascii_whitespace()
        .map(String::from)
        .collect();

    let socks5_addr = env
        .var("SOCKS5_ADDR")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let socks5_user = env
        .var("SOCKS5_USER")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let socks5_pass = env
        .var("SOCKS5_PASS")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let socks5_domains: Vec<String> = env
        .var("SOCKS5_DOMAINS")
        .map(|v| v.to_string())
        .unwrap_or_default()
        .split_ascii_whitespace()
        .map(String::from)
        .collect();
    let socks5 = parse_socks5_config(&socks5_addr, &socks5_user, &socks5_pass);

    let early_data = req.headers().get("sec-websocket-protocol")?;
    let early_data = parse_early_data(early_data)?;

    let WebSocketPair { client, server } = WebSocketPair::new()?;
    server.accept()?;

    wasm_bindgen_futures::spawn_local(async move {
        let events = match server.events() {
            Ok(events) => events,
            Err(err) => {
                console_error!("error: could not open websocket stream: {}", err);
                _ = server.close(Some(1011), Some("websocket stream error"));
                return;
            }
        };

        let socket = WebSocketStream::new(&server, events, early_data);
        let ws_for_mux = server.clone();

        if let Err(err) = run_tunnel(
            socket,
            ws_for_mux,
            user_id,
            &proxy_ip,
            socks5.as_ref(),
            &socks5_domains,
        )
        .await
        {
            console_error!("error: {}", err);
            _ = server.close(Some(1003), Some("invalid request"));
        }
    });

    Response::from_websocket(client)
}

mod protocol {
    pub const VERSION: u8 = 0;
    pub const RESPONSE: [u8; 2] = [0u8; 2];
    pub const NETWORK_TYPE_TCP: u8 = 1;
    pub const NETWORK_TYPE_UDP: u8 = 2;
    pub const ADDRESS_TYPE_IPV4: u8 = 1;
    pub const ADDRESS_TYPE_DOMAIN: u8 = 2;
    pub const ADDRESS_TYPE_IPV6: u8 = 3;
}

mod proxy {
    use std::io::{Error, ErrorKind, Result};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use crate::ext::ReadStringExt;
    use crate::protocol;
    use crate::websocket::WebSocketStream;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use worker::*;

    const COPY_BUF_SIZE: usize = 32 * 1024;

    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    const RELAY_TIMEOUT: Duration = Duration::from_secs(900);
    const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
    const DNS_TIMEOUT: Duration = Duration::from_secs(10);

    fn is_retryable(err: &Error) -> bool {
        matches!(
            err.kind(),
            ErrorKind::ConnectionRefused | ErrorKind::TimedOut | ErrorKind::ConnectionAborted
        )
    }

    #[derive(Clone)]
    pub struct Socks5Config {
        pub host: String,
        pub port: u16,
        pub user: Option<String>,
        pub pass: Option<String>,
    }

    pub fn parse_socks5_config(addr: &str, user: &str, pass: &str) -> Option<Socks5Config> {
        if addr.is_empty() {
            return None;
        }
        let (host, port_str) = addr.rsplit_once(':')?;
        let port: u16 = port_str.parse().ok()?;
        let (user_opt, pass_opt) = if user.is_empty() {
            (None, None)
        } else {
            (Some(user.to_string()), Some(pass.to_string()))
        };
        Some(Socks5Config {
            host: host.to_string(),
            port,
            user: user_opt,
            pass: pass_opt,
        })
    }

    fn matches_socks5_whitelist(target: &str, patterns: &[String]) -> bool {
        patterns.iter().any(|pattern| {
            target == pattern.as_str() || target.ends_with(&format!(".{}", pattern))
        })
    }

    fn build_socks5_auth_request(user: &str, pass: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(3 + user.len() + pass.len());
        buf.push(0x01);
        buf.push(user.len() as u8);
        buf.extend_from_slice(user.as_bytes());
        buf.push(pass.len() as u8);
        buf.extend_from_slice(pass.as_bytes());
        buf
    }

    fn build_socks5_connect_request(target: &str, port: u16) -> Vec<u8> {
        let mut buf = Vec::with_capacity(7 + target.len());
        buf.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
        buf.push(target.len() as u8);
        buf.extend_from_slice(target.as_bytes());
        buf.extend_from_slice(&port.to_be_bytes());
        buf
    }

    struct TunnelRequest {
        network_type: u8,
        remote_port: u16,
        remote_addr: String,
    }

    pub fn parse_early_data(data: Option<String>) -> Result<Option<Vec<u8>>> {
        if let Some(data) = data {
            if !data.is_empty() {
                let mut raw = Vec::with_capacity(data.len());
                raw.extend(data.bytes().filter(|&b| b != b'=').map(|b| match b {
                    b'+' => b'-',
                    b'/' => b'_',
                    _ => b,
                }));
                match URL_SAFE_NO_PAD.decode(&raw) {
                    Ok(early_data) => return Ok(Some(early_data)),
                    Err(err) => return Err(Error::new(ErrorKind::Other, err.to_string())),
                }
            }
        }
        Ok(None)
    }

    pub fn parse_user_id(user_id: &str) -> [u8; 16] {
        let mut iter = user_id.as_bytes().iter().filter_map(|b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        });

        let mut bytes = [0u8; 16];
        for b in &mut bytes {
            let (Some(h), Some(l)) = (iter.next(), iter.next()) else {
                break;
            };
            *b = (h << 4) | l;
        }
        bytes
    }

    pub async fn run_tunnel(
        mut client_socket: WebSocketStream<'_>,
        ws_for_mux: WebSocket,
        user_id: [u8; 16],
        proxy_ip: &[String],
        socks5: Option<&Socks5Config>,
        socks5_domains: &[String],
    ) -> Result<()> {
        let request = tokio::select! {
            result = read_tunnel_request(&mut client_socket, &user_id) => result?,
            _ = Delay::from(HANDSHAKE_TIMEOUT) => {
                return Err(Error::new(
                    ErrorKind::TimedOut,
                    "tunnel handshake timed out",
                ));
            }
        };

        // sing-mux signal: VLESS handshake dest = magic addr → switch to mux mode.
        // The client expects the VLESS RESPONSE before sending the sing-mux session header.
        if crate::singmux::is_mux_dest(&request.remote_addr, request.remote_port) {
            client_socket
                .write_all(&protocol::RESPONSE)
                .await
                .map_err(|e| {
                    Error::new(
                        ErrorKind::ConnectionAborted,
                        format!("mux: send vless response failed: {}", e),
                    )
                })?;
            client_socket.flush().await?;
            return crate::singmux::run_mux_session(
                ws_for_mux,
                client_socket,
                proxy_ip.to_vec(),
                socks5.cloned(),
                socks5_domains.to_vec(),
            )
            .await;
        }

        // process outbound
        match request.network_type {
            protocol::NETWORK_TYPE_TCP => {
                // Fast path: known CF-fronted domain → SOCKS5 directly,
                // skipping the doomed direct attempt.
                if let Some(cfg) = socks5 {
                    if matches_socks5_whitelist(&request.remote_addr, socks5_domains) {
                        return process_socks5_outbound(
                            &mut client_socket,
                            cfg,
                            &request.remote_addr,
                            request.remote_port,
                        )
                        .await;
                    }
                }

                // Step 1: try direct to the requested target.
                let mut last_error = match process_tcp_outbound(
                    &mut client_socket,
                    &request.remote_addr,
                    request.remote_port,
                )
                .await
                {
                    Ok(_) => return Ok(()),
                    Err(e) if is_retryable(&e) => e,
                    Err(e) => return Err(e),
                };

                // Step 2: SOCKS5 auto-fallback. Catches CF-blackholed targets
                // that weren't pre-whitelisted. Logged so the operator can
                // promote frequently-failing domains into SOCKS5_DOMAINS.
                if let Some(cfg) = socks5 {
                    console_log!(
                        "[SOCKS5-AUTO-FALLBACK] {}:{} — direct refused, using SOCKS5",
                        request.remote_addr,
                        request.remote_port
                    );
                    match process_socks5_outbound(
                        &mut client_socket,
                        cfg,
                        &request.remote_addr,
                        request.remote_port,
                    )
                    .await
                    {
                        Ok(_) => return Ok(()),
                        Err(e) if is_retryable(&e) => last_error = e,
                        Err(e) => return Err(e),
                    }
                }

                // Step 3: legacy PROXY_IP fallback chain.
                for target in proxy_ip.iter() {
                    match process_tcp_outbound(
                        &mut client_socket,
                        target.as_str(),
                        request.remote_port,
                    )
                    .await
                    {
                        Ok(_) => return Ok(()),
                        Err(e) if is_retryable(&e) => {
                            last_error = e;
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }

                Err(last_error)
            }
            protocol::NETWORK_TYPE_UDP => {
                process_udp_outbound(&mut client_socket, request.remote_port).await
            }
            unknown => Err(Error::new(
                ErrorKind::InvalidData,
                format!("unsupported network type: {}", unknown),
            )),
        }
    }

    async fn read_tunnel_request(
        client_socket: &mut WebSocketStream<'_>,
        user_id: &[u8; 16],
    ) -> Result<TunnelRequest> {
        if client_socket.read_u8().await? != protocol::VERSION {
            return Err(Error::new(ErrorKind::InvalidData, "invalid version"));
        }

        let mut id_buf = [0u8; 16];
        client_socket.read_exact(&mut id_buf).await?;
        if id_buf != *user_id {
            return Err(Error::new(ErrorKind::InvalidData, "invalid user id"));
        }

        let addon_len = client_socket.read_u8().await? as usize;
        if addon_len > 0 {
            let mut addon_buf = [0u8; 255];
            client_socket
                .read_exact(&mut addon_buf[..addon_len])
                .await?;
        }

        // read network type
        let network_type = client_socket.read_u8().await?;

        // read remote port
        let remote_port = client_socket.read_u16().await?;

        // read remote address
        let remote_addr = match client_socket.read_u8().await? {
            protocol::ADDRESS_TYPE_DOMAIN => {
                let length = client_socket.read_u8().await?;
                client_socket.read_string(length as usize).await?
            }
            protocol::ADDRESS_TYPE_IPV4 => {
                Ipv4Addr::from_bits(client_socket.read_u32().await?).to_string()
            }
            protocol::ADDRESS_TYPE_IPV6 => format!(
                "[{}]",
                Ipv6Addr::from_bits(client_socket.read_u128().await?)
            ),
            _ => {
                return Err(Error::new(ErrorKind::InvalidData, "invalid address type"));
            }
        };

        Ok(TunnelRequest {
            network_type,
            remote_port,
            remote_addr,
        })
    }

    async fn process_tcp_outbound(
        client_socket: &mut WebSocketStream<'_>,
        target: &str,
        port: u16,
    ) -> Result<()> {
        let mut remote_socket = open_direct_socket(target, port).await?;
        relay_to_remote(client_socket, &mut remote_socket, target, port).await
    }

    async fn process_socks5_outbound(
        client_socket: &mut WebSocketStream<'_>,
        cfg: &Socks5Config,
        target: &str,
        target_port: u16,
    ) -> Result<()> {
        let mut remote_socket = open_direct_socket(cfg.host.as_str(), cfg.port).await?;
        socks5_handshake(&mut remote_socket, cfg, target, target_port).await?;
        relay_to_remote(client_socket, &mut remote_socket, target, target_port).await
    }

    /// Connect to `target:port` using the same fallback chain as `run_tunnel`:
    /// SOCKS5 whitelist fast-path → direct → SOCKS5 auto-fallback → PROXY_IP chain.
    /// Returns the connected `Socket` ready for relay, without performing relay.
    /// Used by the mux substream task — its relay path is different from run_tunnel's.
    pub async fn connect_to_target(
        target: &str,
        port: u16,
        proxy_ip: &[String],
        socks5: Option<&Socks5Config>,
        socks5_domains: &[String],
    ) -> Result<Socket> {
        // Whitelisted CF-blackholed domains → straight to SOCKS5.
        if let Some(cfg) = socks5 {
            if matches_socks5_whitelist(target, socks5_domains) {
                let mut sock = open_direct_socket(cfg.host.as_str(), cfg.port).await?;
                socks5_handshake(&mut sock, cfg, target, port).await?;
                return Ok(sock);
            }
        }

        // Direct attempt.
        let mut last_error = match open_direct_socket(target, port).await {
            Ok(sock) => return Ok(sock),
            Err(e) if is_retryable(&e) => e,
            Err(e) => return Err(e),
        };

        // SOCKS5 auto-fallback for CF-blackholed targets not on the whitelist.
        if let Some(cfg) = socks5 {
            console_log!(
                "[SOCKS5-AUTO-FALLBACK] {}:{} — direct refused, using SOCKS5 (mux)",
                target,
                port
            );
            match open_direct_socket(cfg.host.as_str(), cfg.port).await {
                Ok(mut sock) => match socks5_handshake(&mut sock, cfg, target, port).await {
                    Ok(()) => return Ok(sock),
                    Err(e) if is_retryable(&e) => last_error = e,
                    Err(e) => return Err(e),
                },
                Err(e) if is_retryable(&e) => last_error = e,
                Err(e) => return Err(e),
            }
        }

        // Legacy PROXY_IP fallback chain.
        for backup in proxy_ip.iter() {
            match open_direct_socket(backup.as_str(), port).await {
                Ok(sock) => return Ok(sock),
                Err(e) if is_retryable(&e) => {
                    last_error = e;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Err(last_error)
    }

    async fn open_direct_socket(host: &str, port: u16) -> Result<Socket> {
        let remote_socket = Socket::builder().connect(host, port).map_err(|e| {
            Error::new(
                ErrorKind::ConnectionRefused,
                format!("connect to remote failed: {}", e),
            )
        })?;

        tokio::select! {
            result = remote_socket.opened() => {
                result.map_err(|e| {
                    Error::new(
                        ErrorKind::ConnectionRefused,
                        format!("remote socket not opened: {}", e),
                    )
                })?;
            }
            _ = Delay::from(CONNECT_TIMEOUT) => {
                return Err(Error::new(ErrorKind::TimedOut, "connect to remote timed out"));
            }
        }

        Ok(remote_socket)
    }

    async fn socks5_handshake(
        socket: &mut Socket,
        cfg: &Socks5Config,
        target: &str,
        target_port: u16,
    ) -> Result<()> {
        let auth_method: u8 = if cfg.user.is_some() { 0x02 } else { 0x00 };

        socket.write_all(&[0x05, 0x01, auth_method]).await?;

        let mut resp = [0u8; 2];
        socket.read_exact(&mut resp).await?;
        if resp[0] != 0x05 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("socks5: bad version 0x{:02x}", resp[0]),
            ));
        }
        if resp[1] != auth_method {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!("socks5: server rejected method 0x{:02x}", auth_method),
            ));
        }

        if auth_method == 0x02 {
            let user = cfg.user.as_deref().unwrap_or_default();
            let pass = cfg.pass.as_deref().unwrap_or_default();
            let auth_req = build_socks5_auth_request(user, pass);
            socket.write_all(&auth_req).await?;

            let mut auth_resp = [0u8; 2];
            socket.read_exact(&mut auth_resp).await?;
            if auth_resp[1] != 0x00 {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    format!("socks5: auth failed status=0x{:02x}", auth_resp[1]),
                ));
            }
        }

        let connect_req = build_socks5_connect_request(target, target_port);
        socket.write_all(&connect_req).await?;

        let mut head = [0u8; 4];
        socket.read_exact(&mut head).await?;
        if head[0] != 0x05 || head[1] != 0x00 {
            return Err(Error::new(
                ErrorKind::ConnectionRefused,
                format!("socks5: CONNECT failed rep=0x{:02x}", head[1]),
            ));
        }

        match head[3] {
            0x01 => {
                let mut buf = [0u8; 4 + 2];
                socket.read_exact(&mut buf).await?;
            }
            0x03 => {
                let len = socket.read_u8().await? as usize;
                let mut buf = vec![0u8; len + 2];
                socket.read_exact(&mut buf).await?;
            }
            0x04 => {
                let mut buf = [0u8; 16 + 2];
                socket.read_exact(&mut buf).await?;
            }
            atyp => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("socks5: bad ATYP 0x{:02x}", atyp),
                ));
            }
        }

        Ok(())
    }

    async fn relay_to_remote(
        client_socket: &mut WebSocketStream<'_>,
        remote_socket: &mut Socket,
        target: &str,
        port: u16,
    ) -> Result<()> {
        client_socket
            .write_all(&protocol::RESPONSE)
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("send response header failed: {}", e),
                )
            })?;
        client_socket.flush().await?;

        let (mut cr, mut cw) = tokio::io::split(client_socket);
        let (mut rr, mut rw) = tokio::io::split(remote_socket);

        let c2r = async {
            let mut buf = vec![0u8; COPY_BUF_SIZE];
            loop {
                let n = cr.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                rw.write_all(&buf[..n]).await?;
            }
            rw.shutdown().await?;
            Ok::<_, Error>(())
        };
        tokio::pin!(c2r);

        let r2c = async {
            let mut buf = vec![0u8; COPY_BUF_SIZE];
            loop {
                let n = rr.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                cw.write_all(&buf[..n]).await?;
            }
            cw.flush().await?;
            cw.shutdown().await?;
            Ok::<_, Error>(())
        };
        tokio::pin!(r2c);

        let result = tokio::select! {
            result = &mut c2r => {
                let _ = tokio::select! {
                    _ = &mut r2c => {}
                    _ = Delay::from(DRAIN_TIMEOUT) => {}
                };
                result
            }
            result = &mut r2c => {
                let _ = tokio::select! {
                    _ = &mut c2r => {}
                    _ = Delay::from(DRAIN_TIMEOUT) => {}
                };
                result
            }
            _ = Delay::from(RELAY_TIMEOUT) => {
                console_log!("relay timed out: {}:{}", target, port);
                return Ok(());
            }
        };

        if let Err(e) = result {
            console_log!("forward data ended: {}:{} - {}", target, port, e);
        }

        Ok(())
    }

    async fn process_udp_outbound(
        client_socket: &mut WebSocketStream<'_>,
        port: u16,
    ) -> Result<()> {
        if port != 53 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "not supported udp proxy yet",
            ));
        }

        client_socket
            .write_all(&protocol::RESPONSE)
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("send response header failed: {}", e),
                )
            })?;
        client_socket.flush().await?;

        const MAX_DNS_PACKET: usize = 4096;
        let mut buf = [0u8; MAX_DNS_PACKET];

        loop {
            let Ok(len) = client_socket.read_u16().await else {
                return Ok(());
            };
            let len = len as usize;
            if len > MAX_DNS_PACKET {
                return Err(Error::new(ErrorKind::InvalidData, "dns packet too large"));
            }
            client_socket.read_exact(&mut buf[..len]).await?;

            let mut init = RequestInit::new();
            init.method = Method::Post;
            init.headers = Headers::new();
            init.body = Some(buf[..len].to_vec().into());
            _ = init.headers.set("Content-Type", "application/dns-message");

            let request =
                Request::new_with_init("https://1.1.1.1/dns-query", &init).map_err(|e| {
                    Error::new(
                        ErrorKind::Other,
                        format!("create DNS request failed: {}", e),
                    )
                })?;

            let dns_fetch = async {
                let mut response = Fetch::Request(request).send().await.map_err(|e| {
                    Error::new(
                        ErrorKind::ConnectionAborted,
                        format!("send DNS-over-HTTP request failed: {}", e),
                    )
                })?;
                response.bytes().await.map_err(|e| {
                    Error::new(
                        ErrorKind::ConnectionAborted,
                        format!("DNS-over-HTTP response body error: {}", e),
                    )
                })
            };

            let data = tokio::select! {
                result = dns_fetch => result?,
                _ = Delay::from(DNS_TIMEOUT) => {
                    return Err(Error::new(ErrorKind::TimedOut, "DNS query timed out"));
                }
            };

            client_socket.write_u16(data.len() as u16).await?;
            client_socket.write_all(&data).await?;
            client_socket.flush().await?;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::is_retryable;
        use std::io::{Error, ErrorKind};

        #[test]
        fn retries_connection_refused() {
            assert!(is_retryable(&Error::new(ErrorKind::ConnectionRefused, "")));
        }

        #[test]
        fn retries_timed_out() {
            assert!(is_retryable(&Error::new(ErrorKind::TimedOut, "")));
        }

        #[test]
        fn retries_connection_aborted() {
            assert!(is_retryable(&Error::new(ErrorKind::ConnectionAborted, "")));
        }

        #[test]
        fn does_not_retry_invalid_data() {
            assert!(!is_retryable(&Error::new(ErrorKind::InvalidData, "")));
        }

        #[test]
        fn does_not_retry_broken_pipe() {
            assert!(!is_retryable(&Error::new(ErrorKind::BrokenPipe, "")));
        }

        #[test]
        fn parse_socks5_config_empty_addr_returns_none() {
            use super::parse_socks5_config;
            assert!(parse_socks5_config("", "u", "p").is_none());
        }

        #[test]
        fn parse_socks5_config_with_auth() {
            use super::parse_socks5_config;
            let cfg = parse_socks5_config("socks.example.com:41080", "myuser", "mypass").unwrap();
            assert_eq!(cfg.host, "socks.example.com");
            assert_eq!(cfg.port, 41080);
            assert_eq!(cfg.user.as_deref(), Some("myuser"));
            assert_eq!(cfg.pass.as_deref(), Some("mypass"));
        }

        #[test]
        fn parse_socks5_config_without_auth() {
            use super::parse_socks5_config;
            let cfg = parse_socks5_config("host:1080", "", "").unwrap();
            assert!(cfg.user.is_none());
            assert!(cfg.pass.is_none());
        }

        #[test]
        fn parse_socks5_config_rejects_malformed_addr() {
            use super::parse_socks5_config;
            assert!(parse_socks5_config("no-port", "", "").is_none());
            assert!(parse_socks5_config("host:not-a-number", "", "").is_none());
        }

        #[test]
        fn whitelist_matches_exact_domain() {
            use super::matches_socks5_whitelist;
            let patterns = vec!["openai.com".to_string()];
            assert!(matches_socks5_whitelist("openai.com", &patterns));
        }

        #[test]
        fn whitelist_matches_subdomain_via_suffix() {
            use super::matches_socks5_whitelist;
            let patterns = vec!["openai.com".to_string(), "anthropic.com".to_string()];
            assert!(matches_socks5_whitelist("api.openai.com", &patterns));
            assert!(matches_socks5_whitelist("claude.anthropic.com", &patterns));
        }

        #[test]
        fn whitelist_rejects_partial_prefix_match() {
            use super::matches_socks5_whitelist;
            let patterns = vec!["openai.com".to_string()];
            assert!(!matches_socks5_whitelist("badopenai.com", &patterns));
            assert!(!matches_socks5_whitelist("openai.com.evil", &patterns));
        }

        #[test]
        fn whitelist_empty_patterns_match_nothing() {
            use super::matches_socks5_whitelist;
            assert!(!matches_socks5_whitelist("anything.com", &[]));
        }

        #[test]
        fn socks5_auth_request_byte_format() {
            use super::build_socks5_auth_request;
            let req = build_socks5_auth_request("user", "pass");
            assert_eq!(
                req,
                vec![
                    0x01,
                    4, b'u', b's', b'e', b'r',
                    4, b'p', b'a', b's', b's',
                ]
            );
        }

        #[test]
        fn socks5_connect_request_byte_format() {
            use super::build_socks5_connect_request;
            let req = build_socks5_connect_request("openai.com", 443);
            assert_eq!(
                req,
                vec![
                    0x05, 0x01, 0x00, 0x03,
                    10, b'o', b'p', b'e', b'n', b'a', b'i', b'.', b'c', b'o', b'm',
                    0x01, 0xbb,
                ]
            );
        }
    }
}

mod ext {
    use std::io::Result;
    use tokio::io::AsyncReadExt;
    pub trait ReadStringExt {
        async fn read_string(&mut self, n: usize) -> Result<String>;
    }

    impl<T: AsyncReadExt + Unpin + ?Sized> ReadStringExt for T {
        async fn read_string(&mut self, n: usize) -> Result<String> {
            let mut buffer = vec![0u8; n];
            self.read_exact(&mut buffer).await?;
            String::from_utf8(buffer).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid string: {}", e),
                )
            })
        }
    }
}

mod websocket {
    use futures_core::Stream;
    use std::{
        future::Future,
        io::{Error, ErrorKind, Result},
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    use bytes::{BufMut, BytesMut};
    use pin_project::pin_project;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use worker::{Delay, EventStream, WebSocket, WebsocketEvent};

    const WRITE_BUFFER_HIGH_WATERMARK: u32 = 1024 * 1024;
    const FLUSH_BUFFER_LOW_WATERMARK: u32 = 128 * 1024;
    const BACKPRESSURE_POLL_INTERVAL: Duration = Duration::from_millis(50);

    #[pin_project]
    pub struct WebSocketStream<'a> {
        ws: &'a WebSocket,
        #[pin]
        stream: EventStream<'a>,
        #[pin]
        write_delay: Option<Delay>,
        read_buffer: BytesMut,
        closed: bool,
    }

    impl<'a> WebSocketStream<'a> {
        pub fn new(
            ws: &'a WebSocket,
            stream: EventStream<'a>,
            early_data: Option<Vec<u8>>,
        ) -> Self {
            let mut read_buffer = BytesMut::new();
            if let Some(data) = early_data {
                read_buffer.put_slice(&data)
            }

            Self {
                ws,
                stream,
                write_delay: None,
                read_buffer,
                closed: false,
            }
        }

        fn poll_backpressure(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            max_buffered_amount: u32,
        ) -> Poll<Result<()>> {
            let mut this = self.project();

            loop {
                if this.ws.as_ref().buffered_amount() <= max_buffered_amount {
                    this.write_delay.set(None);
                    return Poll::Ready(Ok(()));
                }

                match this.write_delay.as_mut().as_pin_mut() {
                    Some(delay) => match delay.poll(cx) {
                        Poll::Ready(()) => {
                            this.write_delay
                                .set(Some(Delay::from(BACKPRESSURE_POLL_INTERVAL)));
                        }
                        Poll::Pending => return Poll::Pending,
                    },
                    None => {
                        this.write_delay
                            .set(Some(Delay::from(BACKPRESSURE_POLL_INTERVAL)));
                    }
                }
            }
        }
    }

    impl AsyncRead for WebSocketStream<'_> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<()>> {
            let mut this = self.project();

            // If we already saw Close/None, return EOF immediately
            if *this.closed {
                return Poll::Ready(Ok(()));
            }

            // If buffer is empty, we must get at least one message (blocking)
            if this.read_buffer.is_empty() {
                match this.stream.as_mut().poll_next(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(Ok(WebsocketEvent::Message(msg)))) => {
                        if let Some(data) = msg.bytes() {
                            this.read_buffer.put_slice(&data);
                        }
                    }
                    Poll::Ready(Some(Ok(WebsocketEvent::Close(_)))) | Poll::Ready(None) => {
                        *this.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Some(Err(e))) => {
                        *this.closed = true;
                        return Poll::Ready(Err(Error::new(ErrorKind::Other, e.to_string())));
                    }
                }
            }

            // Drain additional ready messages without blocking,
            // but stop on Close/Error to avoid consuming them
            while this.read_buffer.len() < buf.remaining() {
                match this.stream.as_mut().poll_next(cx) {
                    Poll::Ready(Some(Ok(WebsocketEvent::Message(msg)))) => {
                        if let Some(data) = msg.bytes() {
                            this.read_buffer.put_slice(&data);
                        }
                    }
                    Poll::Ready(Some(Ok(WebsocketEvent::Close(_)))) | Poll::Ready(None) => {
                        *this.closed = true;
                        break;
                    }
                    Poll::Ready(Some(Err(e))) => {
                        // If we already have data buffered, deliver it first;
                        // the error will surface on the next poll_read
                        if !this.read_buffer.is_empty() {
                            *this.closed = true;
                            break;
                        }
                        *this.closed = true;
                        return Poll::Ready(Err(Error::new(ErrorKind::Other, e.to_string())));
                    }
                    Poll::Pending => break,
                }
            }

            let amt = std::cmp::min(this.read_buffer.len(), buf.remaining());
            if amt > 0 {
                buf.put_slice(&this.read_buffer.split_to(amt));
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for WebSocketStream<'_> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize>> {
            match self
                .as_mut()
                .poll_backpressure(cx, WRITE_BUFFER_HIGH_WATERMARK)
            {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }

            if let Err(e) = self.ws.send_with_bytes(buf) {
                return Poll::Ready(Err(Error::new(ErrorKind::Other, e.to_string())));
            }

            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
            self.as_mut()
                .poll_backpressure(cx, FLUSH_BUFFER_LOW_WATERMARK)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
            match self
                .as_mut()
                .poll_backpressure(cx, FLUSH_BUFFER_LOW_WATERMARK)
            {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }

            if let Err(e) = self.ws.close(Some(1000), Some("normal close")) {
                return Poll::Ready(Err(Error::new(ErrorKind::Other, e.to_string())));
            }

            Poll::Ready(Ok(()))
        }
    }
}

mod smux {
    use std::io::{Error, ErrorKind, Result};

    use bytes::{BufMut, Bytes, BytesMut};
    use tokio::io::{AsyncRead, AsyncReadExt};

    pub const VERSION_1: u8 = 1;

    pub const CMD_SYN: u8 = 0;
    pub const CMD_FIN: u8 = 1;
    pub const CMD_PSH: u8 = 2;
    pub const CMD_NOP: u8 = 3;
    pub const CMD_UPD: u8 = 4;

    pub const HEADER_LEN: usize = 8;
    pub const MAX_PAYLOAD: usize = u16::MAX as usize;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FrameHeader {
        pub version: u8,
        pub cmd: u8,
        pub length: u16,
        pub sid: u32,
    }

    impl FrameHeader {
        pub fn encode_into(&self, out: &mut [u8; HEADER_LEN]) {
            out[0] = self.version;
            out[1] = self.cmd;
            out[2..4].copy_from_slice(&self.length.to_le_bytes());
            out[4..8].copy_from_slice(&self.sid.to_le_bytes());
        }

        pub fn decode(bytes: &[u8; HEADER_LEN]) -> Result<Self> {
            let version = bytes[0];
            if version != VERSION_1 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("smux: unsupported version {}", version),
                ));
            }
            Ok(Self {
                version,
                cmd: bytes[1],
                length: u16::from_le_bytes([bytes[2], bytes[3]]),
                sid: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            })
        }
    }

    pub async fn read_frame_header(r: &mut (impl AsyncRead + Unpin)) -> Result<FrameHeader> {
        let mut buf = [0u8; HEADER_LEN];
        r.read_exact(&mut buf).await?;
        FrameHeader::decode(&buf)
    }

    fn encode_frame(cmd: u8, sid: u32, payload: &[u8]) -> Bytes {
        debug_assert!(payload.len() <= MAX_PAYLOAD);
        let hdr = FrameHeader {
            version: VERSION_1,
            cmd,
            length: payload.len() as u16,
            sid,
        };
        let mut buf = BytesMut::with_capacity(HEADER_LEN + payload.len());
        let mut hdr_buf = [0u8; HEADER_LEN];
        hdr.encode_into(&mut hdr_buf);
        buf.put_slice(&hdr_buf);
        buf.put_slice(payload);
        buf.freeze()
    }

    pub fn fin_frame(sid: u32) -> Bytes {
        encode_frame(CMD_FIN, sid, &[])
    }

    pub fn psh_frame(sid: u32, payload: &[u8]) -> Bytes {
        encode_frame(CMD_PSH, sid, payload)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn round_trips_psh_header() {
            let hdr = FrameHeader {
                version: VERSION_1,
                cmd: CMD_PSH,
                length: 1234,
                sid: 0xDEAD_BEEF,
            };
            let mut buf = [0u8; HEADER_LEN];
            hdr.encode_into(&mut buf);
            assert_eq!(FrameHeader::decode(&buf).unwrap(), hdr);
        }

        #[test]
        fn length_is_little_endian() {
            let hdr = FrameHeader { version: VERSION_1, cmd: CMD_PSH, length: 0x0100, sid: 0 };
            let mut buf = [0u8; HEADER_LEN];
            hdr.encode_into(&mut buf);
            // 0x0100 LE = [0x00, 0x01]
            assert_eq!(buf[2], 0x00);
            assert_eq!(buf[3], 0x01);
        }

        #[test]
        fn sid_is_little_endian() {
            let hdr = FrameHeader { version: VERSION_1, cmd: CMD_PSH, length: 0, sid: 0x01020304 };
            let mut buf = [0u8; HEADER_LEN];
            hdr.encode_into(&mut buf);
            assert_eq!(&buf[4..8], &[0x04, 0x03, 0x02, 0x01]);
        }

        #[test]
        fn rejects_unknown_version() {
            let buf = [2u8, 0, 0, 0, 0, 0, 0, 0];
            assert!(FrameHeader::decode(&buf).is_err());
        }

        #[test]
        fn psh_frame_layout_matches_wire_spec() {
            let frame = psh_frame(1, b"hello");
            assert_eq!(frame.len(), HEADER_LEN + 5);
            assert_eq!(frame[0], VERSION_1);
            assert_eq!(frame[1], CMD_PSH);
            assert_eq!(&frame[2..4], &5u16.to_le_bytes());
            assert_eq!(&frame[4..8], &1u32.to_le_bytes());
            assert_eq!(&frame[8..], b"hello");
        }

        #[test]
        fn fin_frame_has_zero_payload_length() {
            let frame = fin_frame(42);
            assert_eq!(frame.len(), HEADER_LEN);
            assert_eq!(frame[1], CMD_FIN);
            assert_eq!(&frame[2..4], &0u16.to_le_bytes());
            assert_eq!(&frame[4..8], &42u32.to_le_bytes());
        }
    }
}

mod singmux {
    use std::collections::HashMap;
    use std::io::{Error, ErrorKind, Result};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use bytes::Bytes;
    use futures_channel::mpsc;
    use futures_core::Stream;
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
    use worker::*;

    use crate::ext::ReadStringExt;
    use crate::proxy::{connect_to_target, Socks5Config};
    use crate::smux;
    use crate::websocket::WebSocketStream;

    pub const MAGIC_DEST: &str = "sp.mux.sing-box.arpa";
    pub const MAGIC_PORT: u16 = 444;

    pub fn is_mux_dest(addr: &str, port: u16) -> bool {
        port == MAGIC_PORT && addr == MAGIC_DEST
    }

    const SING_VERSION_0: u8 = 0;
    const SING_VERSION_1: u8 = 1;
    const SING_PROTOCOL_SMUX: u8 = 0;

    // sing-mux StreamRequest flag bits
    const FLAG_UDP: u16 = 0x0001;
    const FLAG_PACKET_ADDR: u16 = 0x0002;

    // sing-mux stream-request address types follow sing-box's SocksaddrSerializer,
    // which uses SOCKS5 (RFC 1928) ATYP values — NOT VLESS's 1/2/3 scheme.
    // Verified against captured mihomo bytes: "example.com" → atype 0x03.
    const ATYP_IPV4: u8 = 1;
    const ATYP_FQDN: u8 = 3;
    const ATYP_IPV6: u8 = 4;

    const MAX_SUBSTREAMS: usize = 64;
    const OUTBOUND_CHUNK: usize = 8 * 1024;
    const SUBSTREAM_INBOX_CAP: usize = 8;
    const WRITER_QUEUE_CAP: usize = 64;
    const WRITE_BUFFER_HIGH_WATERMARK: u32 = 1024 * 1024;
    const BACKPRESSURE_POLL_INTERVAL: Duration = Duration::from_millis(50);
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
    const RELAY_TIMEOUT: Duration = Duration::from_secs(900);
    const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

    async fn read_session_header(r: &mut (impl AsyncRead + Unpin)) -> Result<()> {
        let version = r.read_u8().await?;
        if version != SING_VERSION_0 && version != SING_VERSION_1 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("sing-mux: unsupported version {}", version),
            ));
        }
        let protocol = r.read_u8().await?;
        if protocol != SING_PROTOCOL_SMUX {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "sing-mux: only protocol=smux supported in MVP, got {}",
                    protocol
                ),
            ));
        }
        if version == SING_VERSION_1 {
            let padding_flag = r.read_u8().await?;
            if padding_flag != 0 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "sing-mux: padding not supported in MVP — set padding: false on client",
                ));
            }
        }
        Ok(())
    }

    async fn read_stream_request(
        r: &mut (impl AsyncRead + Unpin),
    ) -> Result<(u16, String, u16)> {
        let mut flags_buf = [0u8; 2];
        r.read_exact(&mut flags_buf).await?;
        let flags = u16::from_be_bytes(flags_buf);

        let atype = r.read_u8().await?;
        let addr = match atype {
            ATYP_IPV4 => {
                let mut b = [0u8; 4];
                r.read_exact(&mut b).await?;
                Ipv4Addr::from(b).to_string()
            }
            ATYP_FQDN => {
                let len = r.read_u8().await? as usize;
                r.read_string(len).await?
            }
            ATYP_IPV6 => {
                let mut b = [0u8; 16];
                r.read_exact(&mut b).await?;
                format!("[{}]", Ipv6Addr::from(b))
            }
            other => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("sing-mux: bad address type 0x{:02x}", other),
                ));
            }
        };

        let mut port_buf = [0u8; 2];
        r.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);

        Ok((flags, addr, port))
    }

    fn encode_stream_response_ok() -> Vec<u8> {
        vec![0u8]
    }

    fn encode_stream_response_err(msg: &str) -> Vec<u8> {
        let msg_bytes = msg.as_bytes();
        // Cap message length so it fits in u16 BE.
        let truncated = if msg_bytes.len() > u16::MAX as usize {
            &msg_bytes[..u16::MAX as usize]
        } else {
            msg_bytes
        };
        let mut buf = Vec::with_capacity(3 + truncated.len());
        buf.push(1u8);
        buf.extend_from_slice(&(truncated.len() as u16).to_be_bytes());
        buf.extend_from_slice(truncated);
        buf
    }

    pub struct SubstreamRead {
        rx: mpsc::Receiver<Bytes>,
        leftover: Bytes,
        eof: bool,
    }

    impl SubstreamRead {
        fn new(rx: mpsc::Receiver<Bytes>) -> Self {
            Self { rx, leftover: Bytes::new(), eof: false }
        }
    }

    impl AsyncRead for SubstreamRead {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<()>> {
            // If we have leftover bytes from a previous Bytes chunk, drain them first.
            if !self.leftover.is_empty() {
                let n = std::cmp::min(self.leftover.len(), buf.remaining());
                let chunk = self.leftover.split_to(n);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                // AsyncRead EOF convention: Ready(Ok(())) with no bytes filled.
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.rx).poll_next(cx) {
                Poll::Ready(Some(chunk)) => {
                    let n = std::cmp::min(chunk.len(), buf.remaining());
                    if n == chunk.len() {
                        buf.put_slice(&chunk);
                    } else {
                        buf.put_slice(&chunk[..n]);
                        self.leftover = chunk.slice(n..);
                    }
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(None) => {
                    self.eof = true;
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }

    async fn writer_loop(ws: WebSocket, mut rx: mpsc::Receiver<Bytes>) {
        while let Some(frame) = rx.next().await {
            loop {
                if ws.as_ref().buffered_amount() <= WRITE_BUFFER_HIGH_WATERMARK as u32 {
                    break;
                }
                Delay::from(BACKPRESSURE_POLL_INTERVAL).await;
            }
            if let Err(e) = ws.send_with_bytes(&frame) {
                console_error!("[mux writer] send failed: {}", e);
                return;
            }
        }
    }

    async fn run_substream(
        sid: u32,
        mut sub_read: SubstreamRead,
        mut writer_tx: mpsc::Sender<Bytes>,
        mut exit_tx: mpsc::UnboundedSender<u32>,
        proxy_ip: Vec<String>,
        socks5: Option<Socks5Config>,
        socks5_domains: Vec<String>,
    ) {
        let result = run_substream_inner(
            sid,
            &mut sub_read,
            &mut writer_tx,
            proxy_ip,
            socks5,
            socks5_domains,
        )
        .await;
        if let Err(e) = result {
            console_log!("[mux sid={}] substream ended: {}", sid, e);
        }
        // Always FIN on exit so the client sees a clean close.
        let _ = writer_tx.send(smux::fin_frame(sid)).await;
        // Notify demux so the HashMap entry is reclaimed without waiting for
        // client FIN. Prevents zombies from filling the MAX_SUBSTREAMS cap.
        let _ = exit_tx.send(sid).await;
    }

    async fn run_substream_inner(
        sid: u32,
        sub_read: &mut SubstreamRead,
        writer_tx: &mut mpsc::Sender<Bytes>,
        proxy_ip: Vec<String>,
        socks5: Option<Socks5Config>,
        socks5_domains: Vec<String>,
    ) -> Result<()> {
        let req_result: Result<(u16, String, u16)> = tokio::select! {
            res = read_stream_request(sub_read) => res,
            _ = Delay::from(HANDSHAKE_TIMEOUT) => {
                Err(Error::new(ErrorKind::TimedOut, "mux: stream request timed out"))
            }
        };
        let (flags, target, port) = match req_result {
            Ok(t) => t,
            Err(e) => {
                let err = encode_stream_response_err(&format!("bad request: {}", e));
                let _ = writer_tx.send(smux::psh_frame(sid, &err)).await;
                return Err(e);
            }
        };

        if flags & FLAG_UDP != 0 || flags & FLAG_PACKET_ADDR != 0 {
            let err = encode_stream_response_err("UDP not supported in MVP");
            writer_tx
                .send(smux::psh_frame(sid, &err))
                .await
                .map_err(|_| Error::new(ErrorKind::BrokenPipe, "writer closed"))?;
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("mux: unsupported flags 0x{:04x}", flags),
            ));
        }

        let mut remote = match connect_to_target(
            &target,
            port,
            &proxy_ip,
            socks5.as_ref(),
            &socks5_domains,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                let err = encode_stream_response_err(&format!("connect: {}", e));
                let _ = writer_tx.send(smux::psh_frame(sid, &err)).await;
                return Err(e);
            }
        };

        let ok = encode_stream_response_ok();
        writer_tx
            .send(smux::psh_frame(sid, &ok))
            .await
            .map_err(|_| Error::new(ErrorKind::BrokenPipe, "writer closed"))?;

        let (mut remote_r, mut remote_w) = tokio::io::split(&mut remote);

        let client_to_remote = async {
            let mut buf = vec![0u8; OUTBOUND_CHUNK];
            loop {
                let n = sub_read.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                remote_w.write_all(&buf[..n]).await?;
            }
            let _ = remote_w.shutdown().await;
            Ok::<_, Error>(())
        };
        tokio::pin!(client_to_remote);

        let remote_to_client = async {
            let mut buf = vec![0u8; OUTBOUND_CHUNK];
            loop {
                let n = remote_r.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                writer_tx
                    .send(smux::psh_frame(sid, &buf[..n]))
                    .await
                    .map_err(|_| Error::new(ErrorKind::BrokenPipe, "writer closed"))?;
            }
            Ok::<_, Error>(())
        };
        tokio::pin!(remote_to_client);

        // Mirror relay_to_remote's drain pattern: when one direction finishes,
        // give the other DRAIN_TIMEOUT to flush before we exit. Loses fewer
        // tail bytes than a hard select! cancellation.
        let result = tokio::select! {
            result = &mut client_to_remote => {
                let _ = tokio::select! {
                    _ = &mut remote_to_client => {}
                    _ = Delay::from(DRAIN_TIMEOUT) => {}
                };
                result
            }
            result = &mut remote_to_client => {
                let _ = tokio::select! {
                    _ = &mut client_to_remote => {}
                    _ = Delay::from(DRAIN_TIMEOUT) => {}
                };
                result
            }
            _ = Delay::from(RELAY_TIMEOUT) => {
                console_log!("[mux sid={}] relay timed out for {}:{}", sid, target, port);
                Ok(())
            }
        };

        result
    }

    /// Main mux session driver. Reads sing-mux session header, then runs the
    /// demux loop in this task. Spawns the writer task and per-substream tasks
    /// via `spawn_local`. All cleanup is via channel-drop propagation.
    pub async fn run_mux_session(
        ws: WebSocket,
        mut ws_stream: WebSocketStream<'_>,
        proxy_ip: Vec<String>,
        socks5: Option<Socks5Config>,
        socks5_domains: Vec<String>,
    ) -> Result<()> {
        read_session_header(&mut ws_stream).await?;

        let (writer_tx, writer_rx) = mpsc::channel::<Bytes>(WRITER_QUEUE_CAP);
        let ws_for_writer = ws.clone();
        wasm_bindgen_futures::spawn_local(async move {
            writer_loop(ws_for_writer, writer_rx).await;
        });

        let (exit_tx, mut exit_rx) = mpsc::unbounded::<u32>();
        let mut substreams: HashMap<u32, mpsc::Sender<Bytes>> = HashMap::new();

        loop {
            // Reap exited substream sids before processing the next frame.
            // Prevents the MAX_SUBSTREAMS cap from filling up with zombies when
            // substream tasks exit (remote EOF, error) without client FIN.
            while let Ok(sid) = exit_rx.try_recv() {
                substreams.remove(&sid);
            }

            let hdr = match smux::read_frame_header(&mut ws_stream).await {
                Ok(h) => h,
                Err(e) if matches!(e.kind(), ErrorKind::UnexpectedEof) => break,
                Err(e) => {
                    console_error!("[mux] frame header read failed: {}", e);
                    return Err(e);
                }
            };

            let payload = if hdr.length > 0 {
                let mut buf = vec![0u8; hdr.length as usize];
                ws_stream.read_exact(&mut buf).await?;
                Bytes::from(buf)
            } else {
                Bytes::new()
            };

            match hdr.cmd {
                smux::CMD_SYN => {
                    if substreams.contains_key(&hdr.sid) {
                        console_error!("[mux] duplicate SYN for sid={}", hdr.sid);
                        return Err(Error::new(ErrorKind::InvalidData, "duplicate SYN"));
                    }
                    if substreams.len() >= MAX_SUBSTREAMS {
                        let err = encode_stream_response_err("too many streams");
                        let _ = writer_tx
                            .clone()
                            .send(smux::psh_frame(hdr.sid, &err))
                            .await;
                        let _ = writer_tx.clone().send(smux::fin_frame(hdr.sid)).await;
                        continue;
                    }

                    let (sub_tx, sub_rx) = mpsc::channel::<Bytes>(SUBSTREAM_INBOX_CAP);
                    substreams.insert(hdr.sid, sub_tx);

                    let sub_read = SubstreamRead::new(sub_rx);
                    let writer_tx_clone = writer_tx.clone();
                    let exit_tx_clone = exit_tx.clone();
                    let proxy_ip_clone = proxy_ip.clone();
                    let socks5_clone = socks5.clone();
                    let socks5_domains_clone = socks5_domains.clone();
                    let sid = hdr.sid;
                    wasm_bindgen_futures::spawn_local(async move {
                        run_substream(
                            sid,
                            sub_read,
                            writer_tx_clone,
                            exit_tx_clone,
                            proxy_ip_clone,
                            socks5_clone,
                            socks5_domains_clone,
                        )
                        .await;
                    });
                }
                smux::CMD_PSH => {
                    if let Some(tx) = substreams.get_mut(&hdr.sid) {
                        // try_send first so we can log when the inbox is full
                        // and the demux loop is about to HoL-block. v1 smux has
                        // no flow control; mihomo's max-connections is the
                        // workaround for a single hot substream stalling siblings.
                        match tx.try_send(payload) {
                            Ok(()) => {}
                            Err(e) if e.is_full() => {
                                console_log!(
                                    "[mux] sid={} inbox full, demux blocking until drain",
                                    hdr.sid
                                );
                                if tx.send(e.into_inner()).await.is_err() {
                                    substreams.remove(&hdr.sid);
                                }
                            }
                            Err(_) => {
                                substreams.remove(&hdr.sid);
                            }
                        }
                    }
                }
                smux::CMD_FIN => {
                    substreams.remove(&hdr.sid);
                }
                smux::CMD_NOP => {
                    // xtaci/smux clients send NOP unilaterally; no echo expected.
                }
                smux::CMD_UPD => {
                    // v2 sliding-window flow control. Ignored in MVP.
                }
                other => {
                    console_log!("[mux] unknown cmd 0x{:02x} sid={}", other, hdr.sid);
                }
            }
        }

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[allow(unused_imports)]
        use tokio::io::AsyncReadExt;

        #[test]
        fn is_mux_dest_recognizes_magic() {
            assert!(is_mux_dest("sp.mux.sing-box.arpa", 444));
            assert!(!is_mux_dest("sp.mux.sing-box.arpa", 443));
            assert!(!is_mux_dest("example.com", 444));
        }

        #[test]
        fn stream_response_ok_is_single_zero_byte() {
            assert_eq!(encode_stream_response_ok(), vec![0u8]);
        }

        #[test]
        fn stream_response_err_layout_matches_spec() {
            let buf = encode_stream_response_err("oops");
            // status(1) + msg_len(2 BE) + msg
            assert_eq!(buf[0], 1u8);
            assert_eq!(&buf[1..3], &4u16.to_be_bytes());
            assert_eq!(&buf[3..], b"oops");
        }

        #[tokio::test]
        async fn parses_v0_session_header() {
            // [ver=0, proto=0=smux]
            let bytes = vec![0u8, 0u8];
            let mut cursor = std::io::Cursor::new(bytes);
            read_session_header(&mut cursor).await.unwrap();
        }

        #[tokio::test]
        async fn parses_v1_session_header_no_padding() {
            // [ver=1, proto=0=smux, padding_flag=0]
            let bytes = vec![1u8, 0u8, 0u8];
            let mut cursor = std::io::Cursor::new(bytes);
            read_session_header(&mut cursor).await.unwrap();
        }

        #[tokio::test]
        async fn rejects_v1_padding_enabled() {
            let bytes = vec![1u8, 0u8, 1u8];
            let mut cursor = std::io::Cursor::new(bytes);
            assert!(read_session_header(&mut cursor).await.is_err());
        }

        #[tokio::test]
        async fn rejects_non_smux_protocol() {
            // yamux = 1, h2mux = 2
            let bytes = vec![0u8, 1u8];
            let mut cursor = std::io::Cursor::new(bytes);
            assert!(read_session_header(&mut cursor).await.is_err());
        }

        #[tokio::test]
        async fn parses_stream_request_with_fqdn() {
            // flags=0(TCP), atype=3(FQDN, SOCKS5-style), len=10, "google.com", port=443 BE
            let mut bytes = vec![0u8, 0u8, ATYP_FQDN, 10];
            bytes.extend_from_slice(b"google.com");
            bytes.extend_from_slice(&443u16.to_be_bytes());
            let mut cursor = std::io::Cursor::new(bytes);
            let (flags, addr, port) = read_stream_request(&mut cursor).await.unwrap();
            assert_eq!(flags, 0);
            assert_eq!(addr, "google.com");
            assert_eq!(port, 443);
        }

        #[tokio::test]
        async fn parses_real_mihomo_stream_request() {
            // Ground-truth bytes captured from mihomo 1.19.26 smux client:
            // flags=0, atype=0x03 (FQDN), len=0x0b, "example.com", port=0x0050 (80),
            // followed by the start of the HTTP payload (must be left for the relay).
            let req: &[u8] = &[
                0x00, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.',
                b'c', b'o', b'm', 0x00, 0x50,
            ];
            let mut payload = req.to_vec();
            payload.extend_from_slice(b"GET / HTTP/1.1\r\n");
            let mut cursor = std::io::Cursor::new(payload);
            let (flags, addr, port) = read_stream_request(&mut cursor).await.unwrap();
            assert_eq!(flags, 0);
            assert_eq!(addr, "example.com");
            assert_eq!(port, 80);
            // Remaining bytes (the HTTP payload) must still be readable for relay.
            let mut rest = Vec::new();
            cursor.read_to_end(&mut rest).await.unwrap();
            assert_eq!(&rest, b"GET / HTTP/1.1\r\n");
        }

        #[tokio::test]
        async fn parses_stream_request_with_ipv4() {
            // flags=0, atype=1(IPv4), [1,2,3,4], port=80 BE
            let bytes = vec![0u8, 0u8, ATYP_IPV4, 1, 2, 3, 4, 0x00, 0x50];
            let mut cursor = std::io::Cursor::new(bytes);
            let (_, addr, port) = read_stream_request(&mut cursor).await.unwrap();
            assert_eq!(addr, "1.2.3.4");
            assert_eq!(port, 80);
        }

        #[tokio::test]
        async fn parses_stream_request_with_ipv6() {
            // flags=0, atype=4(IPv6), 16 bytes (::1), port=443 BE
            let mut bytes = vec![0u8, 0u8, ATYP_IPV6];
            bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            bytes.extend_from_slice(&443u16.to_be_bytes());
            let mut cursor = std::io::Cursor::new(bytes);
            let (_, addr, port) = read_stream_request(&mut cursor).await.unwrap();
            assert_eq!(addr, "[::1]");
            assert_eq!(port, 443);
        }

        #[tokio::test]
        async fn stream_request_udp_flag_round_trips() {
            // flags=1(UDP), atype=1(IPv4), 0.0.0.0:0
            let bytes = vec![0u8, 1u8, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
            let mut cursor = std::io::Cursor::new(bytes);
            let (flags, _, _) = read_stream_request(&mut cursor).await.unwrap();
            assert_eq!(flags & FLAG_UDP, FLAG_UDP);
        }

        #[tokio::test]
        async fn substream_read_yields_bytes_across_frame_boundaries() {
            // Stress test that SubstreamRead correctly spans chunks.
            let (mut tx, rx) = mpsc::channel::<Bytes>(8);
            tx.send(Bytes::from_static(b"hel")).await.unwrap();
            tx.send(Bytes::from_static(b"lo")).await.unwrap();
            drop(tx);

            let mut reader = SubstreamRead::new(rx);
            let mut out = vec![0u8; 5];
            reader.read_exact(&mut out).await.unwrap();
            assert_eq!(&out, b"hello");
        }
    }
}
