mod common;

use common::{dummy_packet, setup_interface, TestInterface};
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
async fn test_client_communication(#[case] config_dir: &str) {
    struct ClientA;
    struct ClientB;
    struct Server;

    let client_a_ch = setup_interface::<ClientA>();
    let client_b_ch = setup_interface::<ClientB>();
    let _server_ch = setup_interface::<Server>();

    let client_config =
        ClientConfig::from_path(&Path::new(config_dir).join("client.toml"), "QUINCY_").unwrap();
    let mut server_config =
        ServerConfig::from_path(&Path::new(config_dir).join("server.toml"), "QUINCY_").unwrap();
    server_config.isolate_clients = false;

    let mut client_a = QuincyClient::new(client_config.clone());
    let mut client_b = QuincyClient::new(client_config);
    let server = QuincyServer::new(server_config).unwrap();

    let ip_client_a = Ipv4Addr::new(10, 0, 0, 2);
    let ip_client_b = Ipv4Addr::new(10, 0, 0, 3);

    tokio::spawn(async move { server.run::<TestInterface<Server>>().await.unwrap() });
    client_a.start::<TestInterface<ClientA>>().await.unwrap();
    client_b.start::<TestInterface<ClientB>>().await.unwrap();

    // Test client A -> client B
    let test_packet = dummy_packet(ip_client_a, ip_client_b);

    client_a_ch
        .tx
        .lock()
        .await
        .send(test_packet.clone())
        .unwrap();

    let recv_packet = client_b_ch.rx.lock().await.recv().await.unwrap();

    assert_eq!(recv_packet, test_packet);
}
