mod common;

use common::{TestInterface, dummy_packet_with_size, setup_interface};
use quincy::config::{Bandwidth, ClientConfig, FromPath, ServerConfig};
use quincy_client::client::QuincyClient;
use quincy_server::server::QuincyServer;
use rstest::rstest;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, Instant};

/// Bandwidth limit used for the test: 32 KiB/sec (256 kbps).
///
/// With this rate, the burst capacity is `max(32 KiB, 64 KiB) = 64 KiB`.
/// Each packet is charged its full wire length (~1.2 KiB).
const TEST_BANDWIDTH: Bandwidth = Bandwidth::from_bytes_per_second(32 * 1024);

/// Payload size used to build the test packets. The resulting IPv4 packet is
/// ~1.2 KiB, comfortably below the tunnel MTU.
const TEST_PAYLOAD_LEN: usize = 1200;

/// Number of packets to send in each direction.
///
/// 96 packets × ~1.2 KiB ≈ 118 KiB, which exceeds the 64 KiB burst capacity
/// so the rate limiter actually throttles.
const PACKETS_PER_DIRECTION: usize = 96;

/// Minimum expected duration for the throttled portion of a single direction.
///
/// Direction 1 sends ~118 KiB: 64 KiB fill the burst, the remaining ~54 KiB
/// take ~1.7 s at 32 KiB/s. Direction 2 is fully throttled at ~3.6 s. We use a
/// generous lower bound to avoid flakiness from scheduling jitter and the 5 ms
/// governor jitter.
const MIN_THROTTLE_DURATION: Duration = Duration::from_millis(500);

#[rstest]
#[case("tests/static/configs/tls_standard")]
#[case("tests/static/configs/tls_hybrid")]
#[case("tests/static/configs/tls_postquantum")]
#[case("tests/static/configs/noise_standard")]
#[case("tests/static/configs/noise_hybrid")]
#[case("tests/static/configs/noise_postquantum")]
#[tokio::test]
async fn test_bandwidth_limiting(#[case] config_dir: &str) {
    struct Client;
    struct Server;

    let client_ch = setup_interface::<Client>();
    let server_ch = setup_interface::<Server>();

    let client_config =
        ClientConfig::from_path(&Path::new(config_dir).join("client.toml"), "QUINCY_").unwrap();
    let mut server_config =
        ServerConfig::from_path(&Path::new(config_dir).join("server.toml"), "QUINCY_").unwrap();
    server_config.default_bandwidth_limit = Some(TEST_BANDWIDTH);

    let mut client = QuincyClient::new(client_config);
    let server = QuincyServer::new(server_config).unwrap();

    let ip_server = Ipv4Addr::new(10, 0, 0, 1);
    let ip_client = Ipv4Addr::new(10, 0, 0, 2);

    tokio::spawn(async move { server.run::<TestInterface<Server>>().await.unwrap() });
    client.start::<TestInterface<Client>>().await.unwrap();

    // ── Direction 1: client → server (ingress) ──────────────────────────
    //
    // Packets enter the client's TUN, traverse QUIC, hit the server-side
    // rate limiter in `process_incoming_data`, then arrive at the server TUN.
    // This drains the burst capacity of the shared limiter.
    let ingress_packet = dummy_packet_with_size(ip_client, ip_server, TEST_PAYLOAD_LEN);

    let start = Instant::now();

    for _ in 0..PACKETS_PER_DIRECTION {
        client_ch
            .tx
            .lock()
            .await
            .send(ingress_packet.clone())
            .unwrap();
    }

    let mut server_rx = server_ch.rx.lock().await;
    for _ in 0..PACKETS_PER_DIRECTION {
        server_rx.recv().await.unwrap();
    }
    drop(server_rx);

    let ingress_elapsed = start.elapsed();

    assert!(
        ingress_elapsed > MIN_THROTTLE_DURATION,
        "Ingress should be throttled, but completed in {ingress_elapsed:?}"
    );

    // ── Direction 2: server → client (egress) ───────────────────────────
    //
    // Packets enter the server's TUN, get dispatched to the connection's
    // egress queue, hit the rate limiter in `process_outgoing_data`, then
    // traverse QUIC to the client TUN. Because the burst was already drained
    // by direction 1, throttling kicks in immediately.
    let egress_packet = dummy_packet_with_size(ip_server, ip_client, TEST_PAYLOAD_LEN);

    let start = Instant::now();

    for _ in 0..PACKETS_PER_DIRECTION {
        server_ch
            .tx
            .lock()
            .await
            .send(egress_packet.clone())
            .unwrap();
    }

    let mut client_rx = client_ch.rx.lock().await;
    for _ in 0..PACKETS_PER_DIRECTION {
        client_rx.recv().await.unwrap();
    }
    drop(client_rx);

    let egress_elapsed = start.elapsed();

    // The burst was already consumed by direction 1, so all ~118 KiB are
    // rate-limited at 32 KiB/s → theoretical ~3.6 seconds. We use a
    // generous lower bound.
    assert!(
        egress_elapsed > MIN_THROTTLE_DURATION,
        "Egress should be throttled, but completed in {egress_elapsed:?}"
    );
}
