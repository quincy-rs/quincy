mod common;

use common::{TestInterface, dummy_packet, setup_interface};
use quincy::config::{ClientConfig, FromPath, ServerConfig};
use quincy_client::client::QuincyClient;
use quincy_server::server::QuincyServer;
use rstest::rstest;
use std::net::Ipv4Addr;
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
