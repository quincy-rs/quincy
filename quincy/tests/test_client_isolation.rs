use crate::common::dummy_packet;
use anyhow::Result;
use common::{
    client_config, make_queue_pair, server_config, TestInterface, TestReceiver, TestSender,
};
use quincy::config::{ClientConfig, ServerConfig};
use quincy_client::client::QuincyClient;
use quincy_server::server::QuincyServer;
use rstest::rstest;
use std::sync::LazyLock;
use std::{net::Ipv4Addr, time::Duration};
use tokio::time::timeout;

mod common;

struct ClientA;
type ClientAInterface = TestInterface<ClientA>;
struct ClientB;
type ClientBInterface = TestInterface<ClientB>;
struct Server;
type ServerInterface = TestInterface<Server>;

pub static TEST_QUEUE_CLIENT_A_SEND: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_CLIENT_A_RECV: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_CLIENT_B_SEND: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_CLIENT_B_RECV: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_SERVER_SEND: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();
pub static TEST_QUEUE_SERVER_RECV: LazyLock<(TestSender, TestReceiver)> = make_queue_pair();

interface_impl_imports!();
interface_impl!(
    ClientAInterface,
    TEST_QUEUE_CLIENT_A_SEND,
    TEST_QUEUE_CLIENT_A_RECV
);
interface_impl!(
    ClientBInterface,
    TEST_QUEUE_CLIENT_B_SEND,
    TEST_QUEUE_CLIENT_B_RECV
);
interface_impl!(
    ServerInterface,
    TEST_QUEUE_SERVER_SEND,
    TEST_QUEUE_SERVER_RECV
);

#[rstest]
#[tokio::test]
async fn test_client_isolation(client_config: ClientConfig, server_config: ServerConfig) {
    let mut client_a: QuincyClient<ClientAInterface> = QuincyClient::new(client_config.clone());
    let mut client_b: QuincyClient<ClientBInterface> = QuincyClient::new(client_config);
    let server = QuincyServer::new(server_config).unwrap();

    let ip_client_a = Ipv4Addr::new(10, 0, 0, 2);
    let ip_client_b = Ipv4Addr::new(10, 0, 0, 3);

    tokio::spawn(async move { server.run::<ServerInterface>().await.unwrap() });
    client_a.start().await.unwrap();
    client_b.start().await.unwrap();

    // Test client A -> client B
    let test_packet = dummy_packet(ip_client_a, ip_client_b);

    TEST_QUEUE_CLIENT_A_RECV
        .0
        .lock()
        .await
        .send(test_packet.clone())
        .unwrap();

    let mut recv_queue = TEST_QUEUE_CLIENT_B_SEND.1.lock().await;

    let recv_result = timeout(Duration::from_secs(1), recv_queue.recv()).await;
    assert!(recv_result.is_err());
}
