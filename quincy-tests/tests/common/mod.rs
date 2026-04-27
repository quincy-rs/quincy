use bytes::{BufMut, Bytes, BytesMut};
use etherparse::PacketBuilder;
use ipnet::IpNet;
use quincy::network::{interface::InterfaceIO, packet::Packet, route::InstalledExclusionRoute};
use std::any::TypeId;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{Mutex, mpsc};

pub type TestSender = Arc<Mutex<UnboundedSender<Bytes>>>;
pub type TestReceiver = Arc<Mutex<UnboundedReceiver<Bytes>>>;

// Thread-local channel registry keyed by `TypeId`.
//
// Each `#[tokio::test]` case runs on its own OS thread with a `current_thread`
// runtime, so thread-local storage provides natural isolation between parallel
// test cases — no locks, no contention.
thread_local! {
    static CHANNEL_REGISTRY: RefCell<HashMap<TypeId, (TestSender, TestReceiver)>> =
        RefCell::new(HashMap::new());
}

/// Test-side channel endpoints for a component.
#[allow(dead_code)]
pub struct TestChannels {
    /// Send data TO the interface (inject packets).
    pub tx: TestSender,
    /// Receive data FROM the interface (capture packets).
    pub rx: TestReceiver,
}

/// A test interface parameterised by a marker type `T`.
///
/// Different marker types produce distinct `TypeId`s, enabling isolated
/// channel lookup from the thread-local registry.
pub struct TestInterface<T> {
    _p: std::marker::PhantomData<T>,
    pub tx: TestSender,
    pub rx: TestReceiver,
}

impl<T> TestInterface<T> {
    /// Creates a new test interface with the given channel endpoints.
    pub fn new(tx: TestSender, rx: TestReceiver) -> Self {
        Self {
            _p: std::marker::PhantomData,
            tx,
            rx,
        }
    }
}

/// Creates fresh channels for a test interface type and registers them.
///
/// The interface-side endpoints are stored in the thread-local registry keyed
/// by `TypeId::of::<T>()`. The test-side endpoints are returned so the test can
/// inject and capture packets.
#[allow(unused)]
pub fn setup_interface<T: 'static>() -> TestChannels {
    let (iface_tx, test_rx) = mpsc::unbounded_channel(); // interface → test
    let (test_tx, iface_rx) = mpsc::unbounded_channel(); // test → interface

    CHANNEL_REGISTRY.with(|registry| {
        registry.borrow_mut().insert(
            TypeId::of::<T>(),
            (
                Arc::new(Mutex::new(iface_tx)),
                Arc::new(Mutex::new(iface_rx)),
            ),
        );
    });

    TestChannels {
        tx: Arc::new(Mutex::new(test_tx)),
        rx: Arc::new(Mutex::new(test_rx)),
    }
}

/// Builds a dummy ICMP echo-request packet with the given source and destination.
#[allow(unused)]
pub fn dummy_packet(src: Ipv4Addr, dest: Ipv4Addr) -> Bytes {
    let mut writer = BytesMut::new().writer();
    PacketBuilder::ipv4(src.octets(), dest.octets(), 20)
        .icmpv4_echo_request(0, 0)
        .write(&mut writer, &[1, 2, 3, 4, 5, 6, 7, 8])
        .unwrap();

    writer.into_inner().into()
}

impl<T: 'static + Send + Sync> InterfaceIO for TestInterface<T> {
    /// Creates a new interface by retrieving channels from the thread-local registry.
    fn create_interface(
        _interface_address: IpNet,
        _mtu: u16,
        _tunnel_gateway: Option<IpAddr>,
        _interface_name: Option<&str>,
    ) -> quincy::Result<Self> {
        let (tx, rx) = CHANNEL_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .remove(&TypeId::of::<T>())
                .expect("channels not registered — call setup_interface::<T>() first")
        });
        Ok(Self::new(tx, rx))
    }

    /// No-op for test interfaces.
    fn configure_routes(
        &self,
        _routes: &[IpNet],
        _remote_address: Option<IpAddr>,
    ) -> quincy::Result<Option<InstalledExclusionRoute>> {
        Ok(None)
    }

    /// No-op for test interfaces.
    fn configure_dns(&self, _dns_servers: &[IpAddr]) -> quincy::Result<()> {
        Ok(())
    }

    /// No-op for test interfaces.
    fn cleanup_dns(&self, _dns_servers: &[IpAddr]) -> quincy::Result<()> {
        Ok(())
    }

    /// No-op for test interfaces.
    fn down(&self) -> quincy::Result<()> {
        Ok(())
    }

    /// Returns the MTU (Maximum Transmission Unit) of the test interface.
    fn mtu(&self) -> u16 {
        1400
    }

    /// Returns the name of the test interface.
    fn name(&self) -> Option<String> {
        Some("test".to_string())
    }

    /// Reads a packet from the test interface.
    async fn read_packet(&self) -> quincy::Result<Packet> {
        let packet_data = self.rx.lock().await.recv().await.unwrap();

        Ok(BytesMut::from(packet_data).into())
    }

    /// Writes a packet to the test interface.
    async fn write_packet(&self, packet: Packet) -> quincy::Result<()> {
        let data = packet.data.clone();

        self.tx.lock().await.send(data).unwrap();

        Ok(())
    }
}
