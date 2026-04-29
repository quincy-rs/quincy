use crate::Result;
use crate::constants::PACKET_CHANNEL_SIZE;
use crate::error::InterfaceError;
use crate::network::dns::{add_dns_servers, delete_dns_servers};
use crate::network::interface::InterfaceIO;
use crate::network::packet::Packet;
use crate::network::route::{InstalledExclusionRoute, add_routes};
use bytes::BytesMut;
use ipnet::IpNet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};
use tun_rs::{AsyncDevice, DeviceBuilder, ToIpv4Address};

pub struct TunRsInterface {
    inner: Arc<AsyncDevice>,
    reader_channel: Mutex<Receiver<Packet>>,
    writer_channel: Sender<Packet>,
    reader_task: JoinHandle<Result<()>>,
    writer_task: JoinHandle<Result<()>>,
    mtu: u16,
    gateway: Option<IpAddr>,
    torn_down: AtomicBool,
}

impl InterfaceIO for TunRsInterface {
    fn create_interface(
        interface_address: IpNet,
        mtu: u16,
        tunnel_gateway: Option<IpAddr>,
        interface_name: Option<&str>,
    ) -> Result<Self>
    where
        Self: Sized,
    {
        let mut builder = DeviceBuilder::new().enable(true).mtu(mtu);
        if let Some(interface_name) = interface_name {
            builder = builder.name(interface_name);
        }

        let builder = match interface_address {
            IpNet::V4(interface_address) => {
                let addr = interface_address.addr();
                let netmask = interface_address.netmask();

                let destination = if cfg!(not(target_os = "windows")) {
                    tunnel_gateway.and_then(|addr| addr.ipv4().ok())
                } else {
                    None
                };

                builder.ipv4(addr, netmask, destination)
            }
            IpNet::V6(interface_address) => {
                let addr = interface_address.addr();
                let netmask = interface_address.netmask();

                builder.ipv6(addr, netmask)
            }
        };

        #[cfg(unix)]
        let builder = builder.packet_information(false);

        #[cfg(all(target_os = "linux", feature = "offload"))]
        let builder = builder.offload(true);

        let interface = builder
            .build_async()
            .map_err(|_| InterfaceError::CreationFailed)?;
        let interface = Arc::new(interface);

        info!(
            "Created interface: {}",
            interface.name().unwrap_or("Unknown".to_string())
        );

        let (reader_channel_tx, reader_channel_rx) =
            tokio::sync::mpsc::channel(PACKET_CHANNEL_SIZE);
        let (writer_channel_tx, writer_channel_rx) =
            tokio::sync::mpsc::channel::<Packet>(PACKET_CHANNEL_SIZE);

        let reader_handle = reader_task(interface.clone(), reader_channel_tx, mtu as usize);
        let writer_handle = writer_task(interface.clone(), writer_channel_rx, mtu as usize);

        Ok(Self {
            inner: interface,
            reader_channel: Mutex::new(reader_channel_rx),
            writer_channel: writer_channel_tx,
            reader_task: reader_handle,
            writer_task: writer_handle,
            mtu,
            gateway: tunnel_gateway,
            torn_down: AtomicBool::new(false),
        })
    }

    fn configure_routes(
        &self,
        routes: &[IpNet],
        remote_address: Option<IpAddr>,
    ) -> Result<Option<InstalledExclusionRoute>> {
        let exclusion_token = add_routes(
            routes,
            &self
                .gateway
                .ok_or_else(|| InterfaceError::ConfigurationFailed {
                    reason: "Missing gateway address on client".to_string(),
                })?,
            &self
                .name()
                .ok_or_else(|| InterfaceError::ConfigurationFailed {
                    reason: "Missing interface name on client".to_string(),
                })?,
            remote_address,
        )?;
        info!("Added routes: {routes:?}");

        Ok(exclusion_token)
    }

    fn configure_dns(&self, dns_servers: &[IpAddr]) -> Result<()> {
        add_dns_servers(
            dns_servers,
            &self
                .name()
                .ok_or_else(|| InterfaceError::ConfigurationFailed {
                    reason: "attempted to configure DNS for interface without name".to_string(),
                })?,
        )?;

        info!("Added DNS servers: {dns_servers:?}");

        Ok(())
    }

    fn cleanup_dns(&self, dns_servers: &[IpAddr]) -> Result<()> {
        delete_dns_servers()?;

        info!("Cleaned up DNS servers: {:?}", dns_servers);

        Ok(())
    }

    fn down(&self) -> Result<()> {
        self.teardown()
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn name(&self) -> Option<String> {
        self.inner
            .name()
            .map_err(|e| error!("Failed to get interface name: {e}"))
            .ok()
    }

    #[inline]
    async fn read_packet(&self) -> Result<Packet> {
        let read_packet = self
            .reader_channel
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| InterfaceError::IoError {
                operation: "failed to receive packet from reader channel".to_string(),
            })?;

        debug!("TUN read bytes: {}", read_packet.len());

        Ok(read_packet)
    }

    #[inline]
    async fn read_packets(&self) -> Result<Vec<Packet>> {
        let mtu = self.mtu() as usize;
        let batch_size = u16::MAX as usize / mtu;

        let mut packets_buf = Vec::with_capacity(batch_size);

        let read_packets = self
            .reader_channel
            .lock()
            .await
            .recv_many(&mut packets_buf, batch_size)
            .await;

        if read_packets == 0 {
            return Err(InterfaceError::IoError {
                operation: "failed to receive packets from reader channel".to_string(),
            }
            .into());
        }

        let packets = packets_buf
            .into_iter()
            .take(read_packets)
            .collect::<Vec<_>>();

        debug!("TUN read packets: {}", packets.len());

        Ok(packets)
    }

    #[inline]
    async fn write_packet(&self, packet: Packet) -> Result<()> {
        let packet_len = packet.len();

        self.writer_channel
            .send(packet)
            .await
            .map_err(|_| InterfaceError::IoError {
                operation: "failed to send packet to writer channel".to_string(),
            })?;

        debug!("TUN sent bytes: {packet_len}");

        Ok(())
    }

    #[inline]
    async fn write_packets(&self, packets: Vec<Packet>) -> Result<()> {
        let packets_len = packets.len();

        if packets_len == 0 {
            debug!("TUN sent packets: {packets_len}");
            return Ok(());
        }

        let permits = self
            .writer_channel
            .reserve_many(packets_len)
            .await
            .map_err(|_| InterfaceError::IoError {
                operation: "failed to reserve writer channel capacity".to_string(),
            })?;

        for (permit, packet) in permits.zip(packets) {
            permit.send(packet);
        }

        debug!("TUN sent packets: {packets_len}");

        Ok(())
    }
}

impl TunRsInterface {
    /// Idempotent teardown shared by `InterfaceIO::down()` and `Drop`: aborts
    /// the I/O tasks and disables the TUN device. Subsequent calls are no-ops.
    fn teardown(&self) -> Result<()> {
        if self.torn_down.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        self.reader_task.abort();
        self.writer_task.abort();

        self.inner
            .enabled(false)
            .map_err(|e| InterfaceError::ConfigurationFailed {
                reason: format!("failed to bring down TUN interface: {e}"),
            })?;

        info!(
            "TUN interface {} is down",
            self.name().unwrap_or("Unknown".to_string())
        );

        Ok(())
    }
}

impl Drop for TunRsInterface {
    fn drop(&mut self) {
        if let Err(e) = self.teardown() {
            warn!("TUN teardown during drop failed: {e}");
        }
    }
}

#[cfg(any(not(target_os = "linux"), not(feature = "offload")))]
fn reader_task(
    interface: Arc<AsyncDevice>,
    reader_channel_tx: Sender<Packet>,
    mtu: usize,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        loop {
            let mut packet_buf = unsafe {
                // SAFETY: recv writes packet data into this buffer before any
                // read-like use of the bytes, including truncate/into on the consumed buf.
                uninitialized_bytes_mut(mtu)
            };

            let size = interface
                .recv(&mut packet_buf)
                .await
                .inspect_err(|e| error!("failed to receive packet: {}", e))?;

            packet_buf.truncate(size);
            let packet = packet_buf.into();

            if reader_channel_tx.is_closed() {
                break;
            }

            reader_channel_tx
                .send(packet)
                .await
                .map_err(|e| InterfaceError::IoError {
                    operation: format!("failed to send packet to reader channel: {e}"),
                })
                .inspect_err(|e| error!("{e}"))?;
        }

        info!("reader task exiting - channel closed");
        Ok(())
    })
}

#[cfg(any(not(target_os = "linux"), not(feature = "offload")))]
fn writer_task(
    interface: Arc<AsyncDevice>,
    mut writer_channel_rx: Receiver<Packet>,
    _mtu: usize,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        loop {
            if writer_channel_rx.is_closed() {
                break;
            }

            let packet = match writer_channel_rx.recv().await {
                Some(packet) => packet,
                None => break,
            };

            interface
                .send(&packet)
                .await
                .inspect_err(|e| error!("failed to send packet: {}", e))?;
        }

        info!("writer task exiting - channel closed");
        Ok(())
    })
}

#[cfg(all(target_os = "linux", feature = "offload"))]
fn reader_task(
    interface: Arc<AsyncDevice>,
    reader_channel_tx: Sender<Packet>,
    mtu: usize,
) -> JoinHandle<Result<()>> {
    use std::iter;
    use tun_rs::{IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

    let batch_size = (u16::MAX as usize / mtu).min(IDEAL_BATCH_SIZE);

    let mut original_buffer = [0; VIRTIO_NET_HDR_LEN + u16::MAX as usize];
    let mut sizes = vec![0; batch_size];

    // Allocate bufs once; only consumed entries are replaced each iteration.
    let mut bufs = iter::repeat_with(|| unsafe {
        // SAFETY: the data is written to before it resized and read
        uninitialized_bytes_mut(mtu)
    })
    .take(batch_size)
    .collect::<Vec<_>>();

    tokio::spawn(async move {
        loop {
            // Reset sizes to prevent stale values from being used on error
            sizes.fill(0);

            let num_packets = interface
                .recv_multiple(&mut original_buffer, &mut bufs, &mut sizes, 0)
                .await;

            let num_packets = match num_packets {
                Ok(num_packets) => Ok(num_packets),
                // gso_split returns ErrTooManySegments after all batch_size output
                // slots have been filled; the first batch_size segments are valid.
                Err(e) if e.to_string() == "ErrTooManySegments" => Ok(batch_size),
                Err(e) => Err(e),
            }
            .inspect_err(|e| error!("failed to receive packets from interface: {e}"))?;

            if reader_channel_tx.is_closed() {
                break;
            }

            for idx in 0..num_packets {
                let size = sizes[idx];

                if size > mtu {
                    error!("packet size from TUN offload {size} B exceeds MTU {mtu} B");
                    continue;
                }

                // Swap out the consumed buf with a fresh allocation;
                // bufs beyond num_packets are untouched by recv_multiple and reused as-is.
                let mut buf = std::mem::replace(&mut bufs[idx], unsafe {
                    // SAFETY: recv_multiple writes packet data into this buffer before any
                    // read-like use of the bytes, including truncate/into on the consumed buf.
                    uninitialized_bytes_mut(mtu)
                });

                buf.truncate(size);
                let packet: Packet = buf.into();

                let send_res = reader_channel_tx.send(packet).await;

                if send_res.is_err() {
                    break;
                }
            }
        }

        info!("reader task exiting - channel closed");
        Ok(())
    })
}

#[cfg(all(target_os = "linux", feature = "offload"))]
fn writer_task(
    interface: Arc<AsyncDevice>,
    mut writer_channel_rx: Receiver<Packet>,
    mtu: usize,
) -> JoinHandle<Result<()>> {
    use tun_rs::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

    let batch_size = (u16::MAX as usize / mtu).min(IDEAL_BATCH_SIZE);
    let send_buf_size = VIRTIO_NET_HDR_LEN * batch_size + batch_size * mtu;

    let mut gro_table = GROTable::default();
    let mut send_buf = BytesMut::with_capacity(send_buf_size);

    tokio::spawn(async move {
        let mut packet_buf: Vec<Packet> = Vec::with_capacity(batch_size);
        let mut send_bufs: Vec<BytesMut> = Vec::with_capacity(batch_size);

        loop {
            // Release previous send_bufs to free refcounts before reserving.
            send_bufs.clear();
            packet_buf.clear();

            send_buf.reserve(send_buf_size);

            let num_packets = writer_channel_rx
                .recv_many(&mut packet_buf, batch_size)
                .await;

            if num_packets == 0 || writer_channel_rx.is_closed() {
                break;
            }

            for packet in packet_buf.drain(..) {
                send_buf.resize(VIRTIO_NET_HDR_LEN, 0);
                send_buf.extend_from_slice(&packet);
                send_bufs.push(send_buf.split());
            }

            interface
                .send_multiple(&mut gro_table, &mut send_bufs, VIRTIO_NET_HDR_LEN)
                .await
                .inspect_err(|e| error!("failed to send packet to interface: {e}"))?;
        }

        info!("writer task exiting - channel closed");
        Ok(())
    })
}

/// Creates a `BytesMut` of `capacity` uninitialized bytes.
///
/// # Safety
/// - the caller must ensure that the memory is initialized before it is read
unsafe fn uninitialized_bytes_mut(capacity: usize) -> BytesMut {
    let mut buf = BytesMut::with_capacity(capacity);

    // SAFETY: the data is being written to and then resized
    // so no uninitialized data is being read
    unsafe { buf.set_len(capacity) };

    buf
}
