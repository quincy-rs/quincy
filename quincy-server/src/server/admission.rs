//! Bounded, per-source admission control for in-flight QUIC handshakes.
//!
//! Peers reach this module only after proving return routability (QUIC Retry),
//! so the pool bounds reachable peers rather than spoofed addresses. A full
//! pool pre-empts its longest-pending handshake so new clients are admitted.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use tokio::task::AbortHandle;
use tracing::debug;

/// Returns the admission bucket of a peer: IPv4 per address, IPv6 per /64.
///
/// IPv4-mapped IPv6 peers (dual-stack listeners) count as the IPv4 address.
fn source_id(remote: SocketAddr) -> IpNet {
    match remote.ip() {
        IpAddr::V4(v4) => Ipv4Net::from(v4).into(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => Ipv4Net::from(v4).into(),
            None => Ipv6Net::new(v6, 64)
                .expect("64 is a valid IPv6 prefix")
                .trunc()
                .into(),
        },
    }
}

/// Identity of one reserved slot; clones share it.
///
/// The `Arc` that is also queued in [`State::order`] is the slot's identity, so
/// no counter can overflow.
pub(crate) type Slot = Arc<SlotInner>;

pub(crate) struct SlotInner {
    /// IP subnet (/32 for IPv4, /64 for IPv6) identifying the host.
    source: IpNet,
    /// Set once the driving task is spawned; pre-emption only aborts slots that
    /// already have one.
    abort: OnceLock<AbortHandle>,
}

/// Admission state, touched only under the admission mutex.
struct State {
    /// Live slots in admission order, oldest first.
    order: VecDeque<Slot>,
    /// Live slots per source bucket.
    per_source: HashMap<IpNet, usize>,
}

impl State {
    /// Removes the oldest slot and its per-source accounting.
    ///
    /// The front of `order` is always live, because [`AdmissionPermit::drop`]
    /// unlinks released slots.
    fn evict_oldest(&mut self) -> Option<Slot> {
        let slot = self.order.pop_front()?;
        self.release_source(slot.source);
        Some(slot)
    }

    /// Drops the accounting of one released slot.
    fn release_source(&mut self, source: IpNet) {
        if let Some(count) = self.per_source.get_mut(&source) {
            *count -= 1;

            if *count == 0 {
                self.per_source.remove(&source);
            }
        }
    }
}

/// Admission control for in-flight QUIC handshakes.
///
/// Create one per accept loop, pass each return-routability-validated
/// `quinn::Incoming` to [`HandshakeAdmission::try_admit`], attach the spawned
/// task's abort handle with [`HandshakeAdmission::attach`], and move the permit
/// into that task. The permit frees its slot on drop, so completion, failure,
/// and cancellation all release it.
pub(crate) struct HandshakeAdmission {
    max_pending: usize,
    max_pending_per_source: usize,
    state: Mutex<State>,
}

/// A reserved handshake slot, released when the permit is dropped.
pub(crate) struct AdmissionPermit {
    slot: Slot,
    admission: Arc<HandshakeAdmission>,
}

impl HandshakeAdmission {
    /// Creates admission control for `max_pending` handshakes overall and
    /// `max_pending_per_source` per source bucket.
    ///
    /// Both values come from `ServerConfig`, where zero is rejected during
    /// deserialization and the per-source limit is validated against the global
    /// one.
    pub(crate) fn new(max_pending: usize, max_pending_per_source: usize) -> Arc<Self> {
        Arc::new(Self {
            max_pending,
            max_pending_per_source,
            state: Mutex::new(State {
                order: VecDeque::new(),
                per_source: HashMap::new(),
            }),
        })
    }

    /// Reserves a handshake slot for `remote`.
    ///
    /// Returns `None` only when the peer's source bucket is full. A full pool
    /// pre-empts (aborts) its longest-pending handshake rather than refusing the
    /// newcomer, because a live handshake completes in a few round trips.
    pub(crate) fn try_admit(self: &Arc<Self>, remote: SocketAddr) -> Option<AdmissionPermit> {
        let source = source_id(remote);
        let mut state = self.lock();

        if state
            .per_source
            .get(&source)
            .is_some_and(|count| *count >= self.max_pending_per_source)
        {
            return None;
        }

        if state.order.len() >= self.max_pending {
            let evicted = state.evict_oldest()?;

            if let Some(abort) = evicted.abort.get() {
                abort.abort();
            }

            debug!("Pre-empting the longest-pending handshake to admit '{remote}'");
        }

        let slot = Arc::new(SlotInner {
            source,
            abort: OnceLock::new(),
        });

        *state.per_source.entry(source).or_default() += 1;
        state.order.push_back(slot.clone());

        Some(AdmissionPermit {
            slot,
            admission: Arc::clone(self),
        })
    }

    /// Records the abort handle of the task driving `slot` so it can be pre-empted.
    pub(crate) fn attach(&self, slot: &Slot, abort: AbortHandle) {
        let _ = slot.abort.set(abort);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl AdmissionPermit {
    /// Returns the slot this permit holds, for [`HandshakeAdmission::attach`].
    pub(crate) fn slot(&self) -> Slot {
        self.slot.clone()
    }
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        let mut state = self.admission.lock();
        let before = state.order.len();
        state.order.retain(|slot| !Arc::ptr_eq(slot, &self.slot));

        // A pre-empted slot is already unlinked; it must not free another one.
        if state.order.len() != before {
            state.release_source(self.slot.source);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn peer(addr: &str) -> SocketAddr {
        SocketAddr::new(addr.parse().unwrap(), 1000)
    }

    #[test]
    fn per_source_limit_is_independent_per_source() {
        let admission = HandshakeAdmission::new(10, 1);

        let _first = admission.try_admit(peer("1.2.3.4")).expect("admission");
        let _second = admission.try_admit(peer("5.6.7.8")).expect("admission");

        assert!(admission.try_admit(peer("1.2.3.4")).is_none());
    }

    #[test]
    fn ipv6_prefixes_share_a_bucket() {
        let admission = HandshakeAdmission::new(10, 2);

        let _a = admission
            .try_admit(peer("2001:db8:1::1"))
            .expect("admission");
        let _b = admission
            .try_admit(peer("2001:db8:1::ffff"))
            .expect("admission");

        assert!(admission.try_admit(peer("2001:db8:1::3")).is_none());

        let _c = admission
            .try_admit(peer("2001:db8:2::1"))
            .expect("admission");
    }

    #[test]
    fn ipv4_mapped_ipv6_uses_the_ipv4_bucket() {
        let admission = HandshakeAdmission::new(10, 1);

        let _a = admission.try_admit(peer("1.2.3.4")).expect("admission");

        assert!(admission.try_admit(peer("::ffff:1.2.3.4")).is_none());
    }

    #[test]
    fn preempts_the_longest_pending_handshake() {
        let admission = HandshakeAdmission::new(2, 2);
        let peer_a = peer("1.1.1.1");

        let permit_a = admission.try_admit(peer_a).expect("first admission");
        let _permit_b = admission.try_admit(peer("2.2.2.2")).expect("admission");
        let _permit_c = admission.try_admit(peer("3.3.3.3")).expect("admission");

        let state = admission.lock();
        assert_eq!(state.order.len(), 2);
        assert!(!state.per_source.contains_key(&source_id(peer_a)));
        assert!(state.per_source.contains_key(&source_id(peer("2.2.2.2"))));
        assert!(state.per_source.contains_key(&source_id(peer("3.3.3.3"))));
        drop(state);

        drop(permit_a);
    }

    #[test]
    fn dropping_a_preempted_permit_does_not_free_another_slot() {
        let admission = HandshakeAdmission::new(2, 2);

        let permit_a = admission
            .try_admit(peer("1.1.1.1"))
            .expect("first admission");
        let _permit_b = admission.try_admit(peer("2.2.2.2")).expect("admission");
        let _permit_c = admission.try_admit(peer("3.3.3.3")).expect("admission");

        drop(permit_a);
        assert_eq!(admission.lock().order.len(), 2);

        let _permit_d = admission.try_admit(peer("4.4.4.4")).expect("admission");

        let state = admission.lock();
        assert_eq!(state.order.len(), 2);
        assert!(!state.per_source.contains_key(&source_id(peer("2.2.2.2"))));
        assert!(state.per_source.contains_key(&source_id(peer("3.3.3.3"))));
        assert!(state.per_source.contains_key(&source_id(peer("4.4.4.4"))));
    }

    #[test]
    fn dropping_permit_frees_slot() {
        let admission = HandshakeAdmission::new(2, 1);

        let permit_a = admission
            .try_admit(peer("1.1.1.1"))
            .expect("first admission");
        let _permit_b = admission.try_admit(peer("2.2.2.2")).expect("admission");

        drop(permit_a);
        assert_eq!(admission.lock().order.len(), 1);

        let _permit_c = admission.try_admit(peer("3.3.3.3")).expect("admission");

        let state = admission.lock();
        assert_eq!(state.order.len(), 2);
        assert!(state.per_source.contains_key(&source_id(peer("2.2.2.2"))));
        assert!(state.per_source.contains_key(&source_id(peer("3.3.3.3"))));
    }

    #[tokio::test]
    async fn preemption_aborts_the_task() {
        let admission = HandshakeAdmission::new(1, 1);

        let permit = admission
            .try_admit(peer("1.1.1.1"))
            .expect("first admission");
        let task = tokio::spawn(std::future::pending::<()>());
        admission.attach(&permit.slot(), task.abort_handle());

        let _newcomer = admission.try_admit(peer("2.2.2.2")).expect("admission");

        let result = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("pre-empted task is aborted");

        assert!(
            result
                .expect_err("aborted task must not succeed")
                .is_cancelled()
        );
    }
}
