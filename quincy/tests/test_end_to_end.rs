use crate::common::{
    client_config, dummy_packet, make_queue_pair, server_config, TestInterface, TestReceiver,
    TestSender,
};
use quincy::config::{ClientConfig, ServerConfig};
use quincy::Result;
use quincy_client::client::QuincyClient;
use quincy_server::server::QuincyServer;
use rstest::rstest;
use std::net::Ipv4Addr;
use std::sync::LazyLock;

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
async fn test_end_to_end_communication(client_config: ClientConfig, server_config: ServerConfig) {
    let mut client: QuincyClient<ClientInterface> = QuincyClient::new(client_config);
    let server = QuincyServer::new(server_config).unwrap();

    let ip_server = Ipv4Addr::new(10, 0, 0, 1);
    let ip_client = Ipv4Addr::new(10, 0, 0, 2);

    tokio::spawn(async move { server.run::<ServerInterface>().await.unwrap() });
    client.start().await.unwrap();

    // Test client -> server
    let test_packet = dummy_packet(ip_client, ip_server);

    TEST_QUEUE_CLIENT_RECV
        .0
        .lock()
        .await
        .send(test_packet.clone())
        .unwrap();

    let recv_packet = TEST_QUEUE_SERVER_SEND.1.lock().await.recv().await.unwrap();

    assert_eq!(test_packet, recv_packet);

    // Test server -> client
    let test_packet = dummy_packet(ip_server, ip_client);

    TEST_QUEUE_SERVER_RECV
        .0
        .lock()
        .await
        .send(test_packet.clone())
        .unwrap();

    let recv_packet = TEST_QUEUE_CLIENT_SEND.1.lock().await.recv().await.unwrap();

    assert_eq!(test_packet, recv_packet);
}
