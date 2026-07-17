mod common;

use common::{TestInterface, setup_interface};
use quincy::config::{ClientConfig, ClientProtocolConfig, FromPath, ServerConfig};
use quincy_client::client::QuincyClient;
use quincy_server::server::QuincyServer;
use rstest::rstest;
use secrecy::SecretString;
use std::path::Path;
use std::time::Duration;
use tokio::time::timeout;

/// Override the client identity with unauthorized credentials.
///
/// For Noise configs, replaces the client private key with one whose public key
/// is not in the users file. For TLS configs, replaces the client certificate
/// with one whose fingerprint is not in the users file. In both cases the server
/// should reject the client during the handshake.
fn make_unauthorized(mut config: ClientConfig) -> ClientConfig {
    match &mut config.protocol {
        ClientProtocolConfig::Noise(noise) => {
            // Use a private key whose public key is NOT in the server's users file
            match noise.key_exchange {
                quincy::config::NoiseKeyExchange::Standard => {
                    noise.private_key =
                        SecretString::from("beNoop47anQv3LUmTwJjZRgoxpMgd22myBcUogJuOaM=");
                }
                quincy::config::NoiseKeyExchange::Hybrid => {
                    noise.private_key = SecretString::from(
                        "JJJGXJVJtTot1B/8wtKO4b6Alah+LkdYayZyl0qsP7PCrX0m+IymVNQ1V363d+ybz4P9TT+iYIQnXbOZFatZ6xpXf2zQfbKX1rAUNVQTFpfpJo/R+ko+hewF7gl+auaMA6oP6tEUdMek1k5grybpENKHpEAJzqPsboGSpQcq+lE=",
                    );
                }
                quincy::config::NoiseKeyExchange::PostQuantum => {
                    noise.private_key = SecretString::from(
                        "9nUtSZ6jlOYRV8OgaYjmCrcbxTRFkVkc6DzcPXwTMnylMn8yI6PRgkWI+x4WoXNK21sd7SPJXfTMh8Gw0Y8AuyHiyPgiMkUf7ZCBCK3R7qI2u+waqEa2szz3LV1IcCiI",
                    );
                }
            }
        }
        ClientProtocolConfig::Tls(tls) => {
            // Use a client certificate whose fingerprint is NOT in the server's users file
            tls.client_certificate_file = Some("tests/static/bad_client_cert.pem".into());
            tls.client_certificate = None;
            tls.client_certificate_key_file = Some("tests/static/bad_client_key.pem".into());
            tls.client_certificate_key = None;
        }
    }
    config
}

#[rstest]
#[case("tests/static/configs/tls_standard")]
#[case("tests/static/configs/tls_hybrid")]
#[case("tests/static/configs/tls_postquantum")]
#[case("tests/static/configs/noise_standard")]
#[case("tests/static/configs/noise_hybrid")]
#[case("tests/static/configs/noise_postquantum")]
#[tokio::test]
async fn test_failed_auth_unauthorized_identity(#[case] config_dir: &str) {
    struct Client;
    struct Server;

    let _client_ch = setup_interface::<Client>();
    let _server_ch = setup_interface::<Server>();

    let client_config =
        ClientConfig::from_path(&Path::new(config_dir).join("client.toml"), "QUINCY_").unwrap();
    let server_config =
        ServerConfig::from_path(&Path::new(config_dir).join("server.toml"), "QUINCY_").unwrap();

    // Replace client identity with one that is NOT authorized
    let bad_client_config = make_unauthorized(client_config);

    let mut client = QuincyClient::new(bad_client_config);
    let server = QuincyServer::new(server_config).unwrap();

    tokio::spawn(async move { server.run::<TestInterface<Server>>().await.unwrap() });

    // The client should fail to connect:
    // - Noise: the handshake itself rejects the unauthorized key (allowed-keys check)
    // - TLS: the handshake succeeds but the server closes the connection after
    //   failing to identify the client's certificate fingerprint in the users file,
    //   causing the client's accept_uni() call to return a connection error.
    //
    // The outer timeout is a safety net to prevent infinite hangs in CI; it should
    // never fire because both protocol modes produce explicit errors.
    let result = timeout(
        Duration::from_secs(5),
        client.start::<TestInterface<Client>>(),
    )
    .await;

    match result {
        Ok(Err(_)) => {
            // Expected: handshake rejection (Noise) or connection closed during
            // IP assignment (TLS)
        }
        Ok(Ok(())) => {
            panic!("Expected connection to fail with unauthorized identity, but it succeeded");
        }
        Err(_) => {
            panic!(
                "Timed out waiting for connection failure — the server should explicitly \
                 reject unauthorized clients, not leave them hanging"
            );
        }
    }
}
