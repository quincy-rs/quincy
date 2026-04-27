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
    let content = r#"
[users.test]
authorized_keys = [
    "bcHh+SkqIZS06B5I9DDbrxvSryROjU4MX8i/u1M7Vyw=",
    "0xM1EMoXmhUTRjL7EYhr4JPHdJXcRLvExNWKI9G4C02OdS59gmRSh34ROy1f02kbi5FCwwLulZd7c76tax3Oho7eQS3AFzA/FVKconCtCVopO6nQaQLB+AZ/NXl4OLSGADWJFE6tk3OOZkyKCc/CioIjzBH88VTICAw2lRkTOyPi8pfla4ySlsPqiJ+NGQ8NMBO7xrETw1JK96ulSUlJOyD2xp/OyUB7sJbjiqwd9Mz1tZONujeOQ4rWt6GIpGN0la1MUJUjLFvevAP9koKGqMXqvFooXKbStkg3l3GmNA8wQK8HMq7c4AYfAVEb6iDsBMJ8i0tLUShJTCxEuZHoWo1AqJmCEgc3AC0LeCshokhdAXsgEMbgs8nnIQhsZCfd9CPZFo5iiAK8WVmEzH8F9HizMgo1WEP+KHkJMq10kIkjDG73GVjrGiFd6lReq7e8SywJNMTgRAacBAw5p3eS8sB6tF/U8kZChjoGkzEAs2mApjVORhB/aYeCkap0E2iWVRxtk74iQ5E5O4qnFY4qOBTxRWfo4nN7qCPdjFrsGiCnVKfSCwbBNkRd9YLjg4PzN1P3xJjVVUlcpmGonHXQ6cX7xWGSwU2m8IBAiUrTWI18yjiMy8tVNSSxYixINRU0uMoV9inc6Yun4g9zZzJ14lKukS25w4KdVheBmXYOchtHi7g+fK9ME20gZLMb8k0jCaH/0A1/+n4ZmUMnu3QAWlV1ExwKhkWy0IU3LIgH6K7s4wC+4YIqVKLVx87sucKkOI/ft7jU42SnpBXCJ6AO9nmFe1yVZnrw2YkbnCBEfKPG+0RBGs5Xl48ZMp908au0+AMMCa/6No43eFzZslaZ1BCpozuHgSWXNgzrWCDkzL4QRYCdQL62AE5+e8l9ob3POHkxWQINqJsNMa4klnR7iXbA1gV+6rjm3DsHJaPHfLcakZmcW4YXGmuSxZpqg0J0ywWQ54FP81dF5YDSRC1lGCo5UcGi22Xa9UiQKZv3taeU9gWV2nN/tXaGlnTYumickiMYLKhGBnbB0RSzgpNmw8l4lGv3Zzv3KazDIJdQqH3TK4e4K3BIvHC7mQWG62xwWKIBOQDdg262dZCOGkWDtj9RcHKb+AkVEpzhtqYn2Wakcn9D2ME/6ituWpR8NX/fOGmqh50xlxKLpheTyL5jOCsb0rOo+jbu2yHTahamxn0Mx0kr8LEMCs21NGV48jvGFX4+cqaQ/BdiGGKlQJCx3DnFjA0hbDtLtI1NE51s2Q0OU72jq5gDmVBXBjaG6T0oaCX2i8LuxGs27IpYs8GWEBGNGw9LzCUmIMaCOR8DeyLi2CZvwGmFUKctWZeG9qnGNAk0UQV0KVqlx5D7VaN7tqOu0AYNxaS5eq+aMDIgkaJWbK6YyTcMMMgcVJMMdscOkiR1gp9HbL/FaDxREkljmD/nGMiqQi3ih2swGrxI138UFW7aB82e0HvR82t0CsDAV89r9yow0Wcbtlc2eqj74ggIa5zidrFIhIoNF3KB6iDuPCpzq5+4K6BdOcVhCSKpQkbsC4KPlrD1HJxs+VgZwioRCLTn6kjqSzkGcAM3JW6pvcHLWx2IbnB1qE/OL//QDX+1nKhGhOIuG4M88XoWgA==",
]
authorized_certs = [
    "sha256:2dba01529210e4e828265d56329df1b85a8f9aedccdd3fef67ab502b57cb0029",
]
address_pool = ["10.0.0.2/32"]
"#;

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
