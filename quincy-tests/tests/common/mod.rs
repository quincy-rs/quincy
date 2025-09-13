use bytes::{BufMut, Bytes, BytesMut};
use etherparse::PacketBuilder;
use quincy::config::{ClientConfig, FromPath, ServerConfig};
use rstest::fixture;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{mpsc, Mutex};

pub type TestSender = Arc<Mutex<UnboundedSender<Bytes>>>;
pub type TestReceiver = Arc<Mutex<UnboundedReceiver<Bytes>>>;

pub struct TestInterface<T> {
    _p: std::marker::PhantomData<T>,
    pub tx: TestSender,
    pub rx: TestReceiver,
}

impl<T> TestInterface<T> {
    pub fn new(tx: TestSender, rx: TestReceiver) -> Self {
        Self {
            _p: std::marker::PhantomData,
            tx,
            rx,
        }
    }
}

#[allow(unused)]
pub fn dummy_packet(src: Ipv4Addr, dest: Ipv4Addr) -> Bytes {
    let mut writer = BytesMut::new().writer();
    PacketBuilder::ipv4(src.octets(), dest.octets(), 20)
        .icmpv4_echo_request(0, 0)
        .write(&mut writer, &[1, 2, 3, 4, 5, 6, 7, 8])
        .unwrap();

    writer.into_inner().into()
}

#[fixture]
pub fn client_config() -> ClientConfig {
    ClientConfig::from_path(Path::new("tests/static/client.toml"), "QUINCY_").unwrap()
}

#[fixture]
pub fn server_config() -> ServerConfig {
    ServerConfig::from_path(Path::new("tests/static/server.toml"), "QUINCY_").unwrap()
}

pub const fn make_queue_pair() -> LazyLock<(TestSender, TestReceiver)> {
    LazyLock::new(|| {
        let (tx, rx) = mpsc::unbounded_channel();
        (Arc::new(Mutex::new(tx)), Arc::new(Mutex::new(rx)))
    })
}

#[macro_export]
macro_rules! interface_impl_imports {
    () => {
        use bytes::BytesMut;
        use ipnet::IpNet;
        use quincy::network::{interface::InterfaceIO, packet::Packet};
        use std::net::IpAddr;
    };
}

#[macro_export]
macro_rules! interface_impl {
    ($name:ident, $test_queue_send:ident, $test_queue_recv:ident) => {
        impl InterfaceIO for $name {
            /// Creates a new interface with the specified parameters.
            fn create_interface(
                _interface_address: IpNet,
                _mtu: u16,
                _tunnel_gateway: Option<IpAddr>,
                _routes: Option<&[IpNet]>,
                _dns_servers: Option<&[IpAddr]>,
            ) -> Result<Self> {
                Ok(Self::new(
                    $test_queue_send.0.clone(),
                    $test_queue_recv.1.clone(),
                ))
            }

            /// Configures the runtime routes for the interface.
            fn configure_routes(&self, _routes: &[IpNet]) -> Result<()> {
                Ok(())
            }

            /// Configures the runtime DNS servers for the interface.
            fn configure_dns(&self, _dns_servers: &[IpAddr]) -> Result<()> {
                Ok(())
            }

            /// Cleans up runtime configuration of routes.
            fn cleanup_routes(&self, _routes: &[IpNet]) -> Result<()> {
                Ok(())
            }

            /// Cleans up runtime configuration of DNS servers.
            fn cleanup_dns(&self, _dns_servers: &[IpAddr]) -> Result<()> {
                Ok(())
            }

            /// Brings the interface down, making it operational.
            fn down(&self) -> Result<()> {
                Ok(())
            }

            /// Returns the MTU (Maximum Transmission Unit) of the interface.
            fn mtu(&self) -> u16 {
                1400
            }

            /// Returns the name of the interface.
            fn name(&self) -> Option<String> {
                Some("test".to_string())
            }

            /// Reads a packet from the interface.
            async fn read_packet(&self) -> Result<Packet> {
                let packet_data = self.rx.lock().await.recv().await.unwrap();

                Ok(BytesMut::from(packet_data).into())
            }

            /// Writes a packet to the interface.
            async fn write_packet(&self, packet: Packet) -> Result<()> {
                let data = packet.data.clone();

                self.tx.lock().await.send(data).unwrap();

                Ok(())
            }
        }
    };
}
