mod common;

use common::{TestInterface, setup_interface};
use quincy::config::{ClientConfig, FromPath, ServerConfig};
use quincy_client::client::QuincyClient;
use quincy_server::server::QuincyServer;
use rstest::rstest;
use std::path::Path;
use std::time::Duration;
use tokio::time::timeout;

/// Creates a temporary users file that gives the test user a per-user address
/// pool restricted to a single IP (`10.0.0.2/32`).
///
/// Returns the path to the temporary file. The caller is responsible for
/// cleanup (the file is created in `std::env::temp_dir()`).
fn write_single_ip_users_file(suffix: &str) -> std::path::PathBuf {
    let content = format!(
        "{}\naddress_pool = [\"10.0.0.2/32\"]\n",
        include_str!("static/users.toml")
    );

    let path = std::env::temp_dir().join(format!("quincy_test_users_{suffix}.toml"));
    std::fs::write(&path, content).expect("failed to write temp users file");
    path
}

#[rstest]
#[case("tests/static/configs/tls_standard")]
#[case("tests/static/configs/tls_hybrid")]
#[case("tests/static/configs/tls_postquantum")]
#[case("tests/static/configs/noise_standard")]
#[case("tests/static/configs/noise_hybrid")]
#[case("tests/static/configs/noise_postquantum")]
#[tokio::test]
async fn test_user_address_pool_exhaustion(#[case] config_dir: &str) {
    struct ClientA;
    struct ClientB;
    struct Server;

    let _client_a_ch = setup_interface::<ClientA>();
    let _client_b_ch = setup_interface::<ClientB>();
    let _server_ch = setup_interface::<Server>();

    let client_config =
        ClientConfig::from_path(&Path::new(config_dir).join("client.toml"), "QUINCY_").unwrap();
    let mut server_config =
        ServerConfig::from_path(&Path::new(config_dir).join("server.toml"), "QUINCY_").unwrap();

    // Point the server at a users file that restricts the test user to a single IP
    let users_file = write_single_ip_users_file(config_dir.replace('/', "_").as_str());
    server_config.users_file = users_file.clone();

    let mut client_a = QuincyClient::new(client_config.clone());
    let mut client_b = QuincyClient::new(client_config);
    let server = QuincyServer::new(server_config).unwrap();

    tokio::spawn(async move { server.run::<TestInterface<Server>>().await.unwrap() });

    // First client should connect successfully (gets 10.0.0.2)
    client_a
        .start::<TestInterface<ClientA>>()
        .await
        .expect("First client should connect successfully");

    // Second client should fail: the user's pool is exhausted (only 10.0.0.2/32)
    // and the server closes the connection after failing to assign an IP.
    let result = timeout(
        Duration::from_secs(5),
        client_b.start::<TestInterface<ClientB>>(),
    )
    .await;

    match result {
        Ok(Err(_)) => {
            // Expected: server rejected the connection due to pool exhaustion
        }
        Ok(Ok(())) => {
            panic!(
                "Expected second connection to fail due to address pool exhaustion, \
                 but it succeeded"
            );
        }
        Err(_) => {
            panic!(
                "Timed out waiting for connection failure — the server should explicitly \
                 reject clients when the address pool is exhausted"
            );
        }
    }

    // Clean up temp file
    let _ = std::fs::remove_file(&users_file);
}
