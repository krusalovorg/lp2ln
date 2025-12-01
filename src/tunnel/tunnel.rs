use async_std::net::{IpAddr, SocketAddr};
use async_std::sync::RwLock;
use async_std::{fs, task};
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;
use std::{str, thread};
use stun_client::*;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[derive(Clone, Debug)]
pub struct Tunnel {
    pub local_port: u16,
    pub public_ip: String,
    pub public_port: u16,
    pub socket: Option<Arc<UdpSocket>>,
    client: Option<SocketAddr>,
    pub is_connected: Arc<RwLock<bool>>,
    packet_tx: Option<mpsc::Sender<String>>,
}

impl Tunnel {
    pub async fn new() -> Self {
        let local_port = rand::thread_rng().gen_range(16000..65535);
        let (public_ip, public_port) = Self::stun(local_port).await;
        let mut is_connected = Arc::new(RwLock::new(false));
        let (packet_tx, _) = mpsc::channel(1024);

        Tunnel {
            local_port,
            public_ip,
            public_port,
            socket: None,
            client: None,
            is_connected,
            packet_tx: Some(packet_tx),
        }
    }

    pub async fn with_port(port: u16) -> Self {
        let (public_ip, public_port) = Self::stun(port).await;
        let (packet_tx, _) = mpsc::channel(1024);

        Tunnel {
            local_port: port,
            public_ip,
            public_port,
            socket: None,
            client: None,
            is_connected: Arc::new(RwLock::new(false)),
            packet_tx: Some(packet_tx),
        }
    }

    pub fn get_public_addr(&self) -> String {
        return format!("{}:{}", self.public_ip, self.public_port);
    }

    async fn load_stun_servers() -> Vec<String> {
        let default_servers = vec![
            "stun.l.google.com:19302",
            "stun1.l.google.com:19302",
            "stun2.l.google.com:19302",
            "stun3.l.google.com:19302",
            "stun4.l.google.com:19302",
            "stun.stunprotocol.org:3478",
            "stun.voipstunt.com:3478",
        ];

        match fs::read_to_string("stun_servers.txt").await {
            Ok(content) => {
                let mut servers: Vec<String> = content
                    .lines()
                    .map(|line| line.trim().to_string())
                    .filter(|line| !line.is_empty())
                    .collect();

                for server in default_servers {
                    if !servers.contains(&server.to_string()) {
                        servers.push(server.to_string());
                    }
                }
                servers
            }
            Err(e) => {
                println!(
                    "[WARNING] Failed to load STUN servers from file: {:?}. Using default servers.",
                    e
                );
                default_servers.into_iter().map(|s| s.to_string()).collect()
            }
        }
    }

    async fn stun(port: u16) -> (String, u16) {
        let client = Client::new(format!("0.0.0.0:{}", port), None).await;
        if let Err(e) = client {
            panic!("Failed to create STUN client: {:?}", e);
        }
        let mut client = client.unwrap();

        let stun_servers = Self::load_stun_servers().await;
        println!("[DEBUG] Loaded {} STUN servers", stun_servers.len());

        let mut last_error = None;
        let mut last_res = None;
        for server in stun_servers {
            println!("[DEBUG] Trying STUN server: {}", server);
            let res = client.binding_request(&server, None).await;
            match res {
                Ok(response) => {
                    println!("[DEBUG] Successfully connected to STUN server: {}", server);
                    last_res = Some(response);
                    break;
                }
                Err(e) => {
                    println!("[DEBUG] Failed to connect to {}: {:?}", server, e);
                    last_error = Some(e);
                    continue;
                }
            }
        }

        if last_res.is_none() {
            if let Some(e) = last_error {
                panic!("Failed to connect to any STUN server. Last error: {:?}", e);
            } else {
                panic!("Failed to connect to any STUN server and no error was recorded");
            }
        }

        let res = last_res.unwrap();

        let xor_mapped_addr = Attribute::get_xor_mapped_address(&res);
        if let Some(addr) = xor_mapped_addr {
            (addr.ip().to_string(), addr.port())
        } else {
            let mapped_addr = Attribute::get_mapped_address(&res);
            if let Some(addr) = mapped_addr {
                (addr.ip().to_string(), addr.port())
            } else {
                panic!(
                    "Failed to get XOR mapped address or Mapped address from STUN response: {:?}",
                    res
                );
            }
        }
    }

    fn get_local_ip() -> Option<IpAddr> {
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if let Ok(()) = socket.connect("8.8.8.8:80") {
                if let Ok(addr) = socket.local_addr() {
                    return Some(addr.ip());
                }
            }
        }
        None
    }

    async fn process_packet_queue(&self, mut rx: mpsc::Receiver<String>) {
        while let Some(packet) = rx.recv().await {
            let client = match self.client {
                Some(addr) => addr,
                None => {
                    println!(
                        "[ERROR] Не удалось отправить пакет: клиент не установлен (client is None)"
                    );
                    continue;
                }
            };

            let socket = match &self.socket {
                Some(sock) => sock,
                None => {
                    println!("[ERROR] Не удалось отправить пакет: сокет не инициализирован (socket is None)");
                    continue;
                }
            };

            match socket.send_to(packet.as_bytes(), client).await {
                Ok(_) => println!("[DEBUG] Пакет успешно отправлен к {}", client),
                Err(e) => println!("[ERROR] Не удалось отправить пакет к {}: {:?}", client, e),
            }
        }
    }

    pub async fn send_packet(&self, packet: &String) {
        if let Some(tx) = &self.packet_tx {
            if let Err(e) = tx.send(packet.clone()).await {
                println!("[ERROR] Не удалось отправить пакет в очередь: {:?}", e);
            }
        } else {
            println!("[ERROR] Канал отправки пакетов не инициализирован");
        }
    }

    pub async fn make_connection(
        &mut self,
        ip: &str,
        port: u16,
        timeout_default: u64,
    ) -> Result<(), String> {
        println!("[STUN] make_connection");
        println!("[STUN] IP: {}", ip);
        println!("[STUN] Public IP: {}", self.public_ip);
        let local_ip = match Self::get_local_ip() {
            Some(ip) => ip.to_string(),
            None => return Err("[STUN] Не удалось определить локальный IP".to_string()),
        };
        println!("[STUN] Локальный IP: {}", local_ip);

        let addr = format!("{}:{}", ip, port)
            .parse::<SocketAddr>()
            .expect("Invalid address");
        let local_port = self.local_port;
        let mut timeout_count = timeout_default;
        println!("[STUN] Trying to connect to {}:{}", ip, port);

        while timeout_count > 0 {
            let sock = match UdpSocket::bind(format!("0.0.0.0:{}", local_port)).await {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    return Err(format!("[STUN] Failed to bind UDP socket: {:?}", e));
                }
            };

            println!(
                "[STUN] Sending connection request to {}:{}... {}/{}",
                ip, port, timeout_count, timeout_default
            );

            if let Err(e) = sock.send_to(b"KPL", addr).await {
                println!("[STUN] Failed to send connection request: {:?}", e);
                timeout_count -= 1;
                continue;
            }

            let mut buf = vec![0u8; 1024];
            match timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await {
                Ok(res) => match res {
                    Ok((_n, peer)) => {
                        println!(
                            "[STUN] Reply received from {}:{}...",
                            peer.ip(),
                            peer.port()
                        );
                        if let Err(e) = sock.send_to(b"KPL", addr).await {
                            println!("[STUN] Failed to resend connection request: {:?}", e);
                            timeout_count -= 1;
                            continue;
                        }
                        self.client = Some(addr);
                        self.socket = Some(sock.clone());
                        self.is_connected = Arc::new(RwLock::new(true));

                        if let Some(tx) = self.packet_tx.take() {
                            let (new_tx, rx) = mpsc::channel(1024);
                            self.packet_tx = Some(new_tx);

                            let tunnel_clone = self.clone();
                            tokio::spawn(async move {
                                tunnel_clone.process_packet_queue(rx).await;
                            });
                        }

                        println!("[STUN] Hole with {} successfully broken!", addr);
                        return Ok(());
                    }
                    Err(e) => {
                        timeout_count -= 1;
                        println!("[STUN] Error while receiving data: {:?}", e);
                    }
                },
                Err(_) => {
                    timeout_count -= 1;
                    println!("[STUN] No handshake with {}:{} yet...", ip, port);
                }
            }
        }
        self.is_connected = Arc::new(RwLock::new(false));
        if self.client.is_none() {
            return Err(format!(
                "[STUN] Failed to establish connection with {}:{}",
                ip, port
            ));
        }
        Err(format!(
            "[STUN] Failed to establish connection with {}:{}",
            ip, port
        ))
    }

    pub fn backlife_cycle(&self, freq: u64) {
        if let Some(client) = self.client {
            if let Some(sock) = &self.socket {
                let sock = sock.clone();
                thread::spawn(move || {
                    Self::life_cycle(sock, client, freq);
                });
                println!("[STUN] Session with {} stabilized!", client);
            }
        } else {
            println!("[STUN] No client to stabilize session with.");
        }
    }

    fn life_cycle(sock: Arc<UdpSocket>, client: SocketAddr, freq: u64) {
        println!("[STUN] Starting life cycle...");
        let sock_clone = sock.clone();

        thread::spawn(move || loop {
            let _ = task::block_on(sock_clone.send_to(b"KPL", client)).map_err(|e| {
                println!("[STUN] Failed to send keep-alive packet: {:?}", e);
            });
            thread::sleep(Duration::from_secs_f64(1.0 / freq as f64));
        });
    }

    pub fn get_public_ip(&self) -> String {
        self.public_ip.clone()
    }

    pub fn get_public_port(&self) -> u16 {
        self.public_port
    }

    pub async fn is_connected(&self) -> bool {
        *self.is_connected.read().await
    }
}
