use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

use crate::packet::Packet;
use crate::sessions::IncomingPacket;

use super::admission::{IngressBudget, IngressPermit};

struct Ring {
    tx: broadcast::Sender<Arc<IncomingPacket>>,
    charges: VecDeque<Arc<IngressPermit>>,
}

impl Ring {
    fn new(capacity: usize) -> Self {
        Self {
            tx: broadcast::channel(capacity).0,
            charges: VecDeque::new(),
        }
    }

    fn reap(&mut self) {
        let released = self.charges.len().saturating_sub(self.tx.len());
        self.charges.drain(..released);
    }

    fn send(&mut self, packet: &Arc<IncomingPacket>, permit: &Arc<IngressPermit>) {
        if self.tx.send(packet.clone()).is_ok() {
            self.charges.push_back(permit.clone());
            self.reap();
        }
    }
}

pub(crate) struct LegacyFanout {
    rings: Mutex<Option<(Ring, Ring)>>,
    budget: Arc<IngressBudget>,
}

impl LegacyFanout {
    pub(crate) fn new(capacity: usize, budget: Arc<IngressBudget>) -> Self {
        Self {
            rings: Mutex::new(Some((Ring::new(capacity), Ring::new(capacity)))),
            budget,
        }
    }

    pub(crate) fn subscribe(
        &self,
        authenticated: bool,
    ) -> broadcast::Receiver<Arc<IncomingPacket>> {
        let rings = self.rings.lock().unwrap();
        match rings.as_ref() {
            Some((_, auth)) if authenticated => auth.tx.subscribe(),
            Some((legacy, _)) => legacy.tx.subscribe(),
            None => broadcast::channel(1).1,
        }
    }

    pub(crate) fn close(&self) {
        self.rings.lock().unwrap().take();
    }

    pub(crate) fn reap(&self) {
        if let Some((raw, auth)) = self.rings.lock().unwrap().as_mut() {
            raw.reap();
            auth.reap();
        }
    }

    pub(crate) fn publish(&self, ip: &IncomingPacket) {
        self.publish_packet(&ip.session_id, ip.from_node.as_deref(), &ip.packet, false);
    }

    pub(crate) fn publish_packet(
        &self,
        session: &str,
        peer: Option<&str>,
        packet: &Packet,
        authenticated: bool,
    ) {
        let mut state = self.rings.lock().unwrap();
        let Some(rings) = state.as_mut() else {
            return;
        };
        rings.0.reap();
        rings.1.reap();
        let raw_active = rings.0.tx.receiver_count() > 0;
        let auth_active = authenticated && rings.1.tx.receiver_count() > 0;
        if !raw_active && !auth_active {
            return;
        }

        // reserve the allocation before cloning; both ring slots point to it.
        let bytes = super::admission::retained_packet_bytes(
            session.len(),
            peer.map_or(0, str::len),
            packet,
        );
        let Some(permit) = self.budget.fanout(bytes, None) else {
            return;
        };
        let permit = Arc::new(permit);
        let shared = Arc::new(IncomingPacket {
            session_id: session.to_owned(),
            from_node: peer.map(str::to_owned),
            packet: packet.clone(),
        });
        if raw_active {
            rings.0.send(&shared, &permit);
        }
        if auth_active {
            rings.1.send(&shared, &permit);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rings_share_one_charge_until_the_last_core_reference_leaves() {
        let budget = Arc::new(IngressBudget::default());
        let fanout = LegacyFanout::new(4, budget.clone());
        let mut raw = fanout.subscribe(false);
        let mut auth = fanout.subscribe(true);
        let packet = Packet {
            signature: None,
            data: vec![1; 16 * 1024],
            nodes: vec![],
            sender: "source".into(),
            receiver: "dest".into(),
            max_hops: 1,
            request_id: None,
            protocol_id: None,
            chunk_stream_id: None,
            chunk_index: None,
            total_chunks: None,
        };
        fanout.publish_packet("s", Some("p"), &packet, true);
        let charged = budget.snapshot().fanout_bytes;
        assert!((packet.data.len()..packet.data.len() + 1024).contains(&charged));
        let raw_packet = raw.recv().await.unwrap();
        fanout.reap();
        assert_eq!(budget.snapshot().fanout_bytes, charged);
        let auth_packet = auth.recv().await.unwrap();
        assert!(Arc::ptr_eq(&raw_packet, &auth_packet));
        fanout.reap();
        assert_eq!(budget.snapshot().fanout_bytes, 0);
        // Both external Arc values can outlive the Core's accounting.
        assert_eq!(raw_packet.packet.data.len(), 16 * 1024);
    }
}
