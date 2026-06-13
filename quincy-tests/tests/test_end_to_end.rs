mod common;

use common::{TestInterface, dummy_packet, setup_interface};
use quincy::QuincyError;
use quincy::config::{ClientConfig, FromPath, ServerConfig};
use quincy::network::interface::Interface;
use quincy_client::client::QuincyClient;
use quincy_server::server::QuincyServer;
use rstest::rstest;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

#[rstest]
#[case("tests/static/configs/tls_standard")]
#[case("tests/static/configs/tls_hybrid")]
#[case("tests/static/configs/tls_postquantum")]
#[case("tests/static/configs/noise_standard")]
#[case("tests/static/configs/noise_hybrid")]
#[tokio::test]
async fn test_end_to_end_communication(#[case] config_dir: &str) {
    struct Client;
    struct Server;

    let client_ch = setup_interface::<Client>();
    let server_ch = setup_interface::<Server>();

    let client_config =
        ClientConfig::from_path(&Path::new(config_dir).join("client.toml"), "QUINCY_").unwrap();
    let server_config =
        ServerConfig::from_path(&Path::new(config_dir).join("server.toml"), "QUINCY_").unwrap();

    let mut client = QuincyClient::new(client_config);
    let server = QuincyServer::new(server_config).unwrap();

    let ip_server = Ipv4Addr::new(10, 0, 0, 1);
    let ip_client = Ipv4Addr::new(10, 0, 0, 2);

    tokio::spawn(async move { server.run::<TestInterface<Server>>().await.unwrap() });
    client.start::<TestInterface<Client>>().await.unwrap();

    assert_eq!(
        client.client_address().map(|addr| addr.addr()),
        Some(IpAddr::V4(ip_client))
    );
    assert_eq!(
        client.server_address().map(|addr| addr.addr()),
        Some(IpAddr::V4(ip_server))
    );

    // Test client -> server
    let test_packet = dummy_packet(ip_client, ip_server);

    client_ch.tx.lock().await.send(test_packet.clone()).unwrap();

    let recv_packet = server_ch.rx.lock().await.recv().await.unwrap();

    assert_eq!(test_packet, recv_packet);

    // Test server -> client
    let test_packet = dummy_packet(ip_server, ip_client);

    server_ch.tx.lock().await.send(test_packet.clone()).unwrap();

    let recv_packet = client_ch.rx.lock().await.recv().await.unwrap();

    assert_eq!(test_packet, recv_packet);
}

#[tokio::test]
async fn test_start_with_interface_failure_leaves_client_stopped() {
    struct Client;
    struct Server;

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

    server_config.bind_port = 55165;
    client_config.connection_string = "localhost:55165".to_string();

    let mut client = QuincyClient::new(client_config);
    let server = QuincyServer::new(server_config).unwrap();

    tokio::spawn(async move { server.run::<TestInterface<Server>>().await.unwrap() });

    let result = client
        .start_with_interface::<TestInterface<Client>, _>(|interface_config| {
            assert_eq!(
                interface_config.client_address.addr().to_string(),
                "10.0.0.2"
            );
            assert_eq!(
                interface_config.server_address.addr().to_string(),
                "10.0.0.1"
            );
            assert_eq!(interface_config.mtu, 1400);

            Err::<Interface<TestInterface<Client>>, _>(QuincyError::system(
                "forced interface creation failure",
            ))
        })
        .await;

    assert!(result.is_err());
    assert!(!client.is_running());
    assert_eq!(client.client_address(), None);
    assert_eq!(client.server_address(), None);
}

#[cfg(unix)]
#[tokio::test]
async fn test_start_with_tun_fd_failure_closes_fd_and_leaves_client_stopped() {
    use std::cell::Cell;
    use std::fs::File;
    use std::os::fd::{AsRawFd, OwnedFd};

    struct Server;

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

    server_config.bind_port = 55166;
    client_config.connection_string = "localhost:55166".to_string();

    let mut client = QuincyClient::new(client_config);
    let server = QuincyServer::new(server_config).unwrap();
    let raw_fd = Cell::new(-1);

    tokio::spawn(async move { server.run::<TestInterface<Server>>().await.unwrap() });

    // SAFETY: the callback returns an owned fd, intentionally using a non-TUN
    // fd to exercise the rejected construction path.
    let result = unsafe {
        client
            .start_with_tun_fd(|interface_config| {
                assert_eq!(
                    interface_config.client_address.addr().to_string(),
                    "10.0.0.2"
                );
                assert_eq!(interface_config.mtu, 1400);

                let file = File::open("/dev/null").expect("open /dev/null");
                raw_fd.set(file.as_raw_fd());
                Ok::<OwnedFd, QuincyError>(file.into())
            })
            .await
    };

    assert!(result.is_err());
    assert!(!client.is_running());
    assert_eq!(client.client_address(), None);
    assert_eq!(client.server_address(), None);

    // SAFETY: the descriptor number is only inspected after ownership moved
    // into `start_with_tun_fd` and construction failed.
    let flags = unsafe { libc::fcntl(raw_fd.get(), libc::F_GETFD) };
    assert_eq!(flags, -1);
}
