mod common;

use common::{setup_interface, TestInterface};
use quincy::config::{ClientConfig, FromPath, ServerConfig};
use quincy_client::client::QuincyClient;
use quincy_server::server::QuincyServer;
use rstest::rstest;
use std::path::Path;

#[rstest]
#[case("tests/static/configs/tls_standard")]
#[case("tests/static/configs/tls_hybrid")]
#[case("tests/static/configs/tls_postquantum")]
#[case("tests/static/configs/noise_standard")]
#[case("tests/static/configs/noise_hybrid")]
#[tokio::test]
async fn test_failed_auth(#[case] config_dir: &str) {
    struct Client;
    struct Server;

    let _client_ch = setup_interface::<Client>();
    let _server_ch = setup_interface::<Server>();

    let mut client_config =
        ClientConfig::from_path(&Path::new(config_dir).join("client.toml"), "QUINCY_").unwrap();
    client_config.authentication.password = "wrong_password".to_string();

    let server_config =
        ServerConfig::from_path(&Path::new(config_dir).join("server.toml"), "QUINCY_").unwrap();

    let mut client = QuincyClient::new(client_config);
    let server = QuincyServer::new(server_config).unwrap();

    tokio::spawn(async move { server.run::<TestInterface<Server>>().await });
    assert!(client.start::<TestInterface<Client>>().await.is_err());
}
