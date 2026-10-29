mod common;

use common::{TestInterface, setup_interface, use_ephemeral_server_port};
use quincy::config::{ClientConfig, FromPath, ServerConfig};
use quincy::constants::QUINN_RUNTIME;
use quincy::network::socket::bind_socket;
use quincy_client::client::QuincyClient;
use quincy_server::server::QuincyServer;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Unvalidated (never return-routability-checked) Initials must not consume
/// handshake slots.
///
/// The flood reaches the server through a proxy that forwards client -> server
/// and drops server -> client, so every flooded Initial stays unvalidated (the
/// server's Retry never arrives) and the flood shares the legitimate client's
/// source network. Without the Retry gate the flood alone exhausts the
/// per-source handshake limit for that network and the legitimate client is
/// never admitted.
#[tokio::test]
async fn test_unvalidated_initial_flood_does_not_block_legit_client() {
    struct Client;
    struct Server;

    let _client_ch = setup_interface::<Client>();
    let _server_ch = setup_interface::<Server>();

    let mut client_config = ClientConfig::from_path(
        Path::new("tests/static/configs/tls_standard/client.toml"),
        "QUINCY_",
    )
    .unwrap();
    let mut server_config = ServerConfig::from_path(
        Path::new("tests/static/configs/tls_standard/server.toml"),
        "QUINCY_",
    )
    .unwrap();
    use_ephemeral_server_port(&mut client_config, &mut server_config);

    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_config.bind_port);

    // `localhost` resolves to 127.0.0.1 here, which puts the legitimate client
    // in the same admission bucket as the flooded peers below.
    let flood_config = client_config.quinn_client_config().unwrap();

    let server = QuincyServer::new(server_config).unwrap();
    tokio::spawn(async move { server.run::<TestInterface<Server>>().await.unwrap() });

    // Drop proxy: forwards client -> server, never server -> client, so the
    // flooded peers never learn they were asked to retry.
    let proxy = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let upstream = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    upstream.connect(server_addr).await.unwrap();

    tokio::spawn(async move {
        let mut buffer = vec![0u8; 2048];

        loop {
            let Ok((len, _)) = proxy.recv_from(&mut buffer).await else {
                return;
            };
            let _ = upstream.send(&buffer[..len]).await;
        }
    });

    // 32 attempts > the default per-source limit (8): every one of them sends
    // an Initial that never gets an answer, so all of them stay unvalidated.
    let socket = bind_socket(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        client_config.connection.send_buffer_size as usize,
        client_config.connection.recv_buffer_size as usize,
        false,
    )
    .unwrap();
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        QUINN_RUNTIME.clone(),
    )
    .unwrap();
    let _flood: Vec<_> = (0..32)
        .filter_map(|_| {
            endpoint
                .connect_with(flood_config.clone(), proxy_addr, "localhost")
                .ok()
        })
        .collect();

    // Give the server time to process the flood, then connect for real.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut client = QuincyClient::new(client_config);
    let started = timeout(
        Duration::from_secs(5),
        client.start::<TestInterface<Client>>(),
    )
    .await
    .expect("legitimate client was blocked by unvalidated handshake flood");

    started.unwrap();
}
