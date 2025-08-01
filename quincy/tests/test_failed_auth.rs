use crate::common::{
    client_config, make_queue_pair, server_config, TestInterface, TestReceiver, TestSender,
};
use anyhow::Result;
use quincy::config::{ClientConfig, ServerConfig};
use quincy_client::client::QuincyClient;
use quincy_server::server::QuincyServer;
use rstest::rstest;
use std::sync::LazyLock;
use tracing_test::traced_test;

mod common;

struct Client;
type ClientInterface = TestInterface<Client>;
struct Server;
type ServerInterface = TestInterface<Server>;

pub static TEST_QUEUE_CLIENT_SEND: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_CLIENT_RECV: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_SERVER_SEND: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_SERVER_RECV: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();

interface_impl_imports!();
interface_impl!(
    ClientInterface,
    TEST_QUEUE_CLIENT_SEND,
    TEST_QUEUE_CLIENT_RECV
);
interface_impl!(
    ServerInterface,
    TEST_QUEUE_SERVER_SEND,
    TEST_QUEUE_SERVER_RECV
);

#[rstest]
#[tokio::test]
#[traced_test]
async fn test_failed_auth(mut client_config: ClientConfig, server_config: ServerConfig) {
    client_config.authentication.password = "wrong_password".to_string();
    let mut client: QuincyClient<ClientInterface> = QuincyClient::new(client_config);
    let server = QuincyServer::new(server_config).unwrap();

    tokio::spawn(async move { server.run::<ServerInterface>().await });
    assert!(client.start().await.is_err());

    assert!(logs_contain("Failed to authenticate client"));
}
