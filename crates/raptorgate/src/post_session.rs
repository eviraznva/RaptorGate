use std::sync::Arc;

use etherparse::NetSlice;
use tokio::sync::{broadcast, mpsc};

use crate::conntrack::entry::CtInfo;
use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::{CaptureDirection, PacketContext};
use crate::data_plane::tun_forwarder::TunForwarder;
use crate::interfaces::InterfaceMonitor;
use crate::l4::release::{PacketDispositionEvent, PacketDispositionOutcome, ReleaseAction};
use crate::nat::NatEngine;
use crate::netlink::routing_table::RouteLookup;

pub fn apply_nat_postrouting<M, R>(
    packet: &mut PacketContext,
    engine: &NatEngine,
    routes: &R,
    interface_monitor: &M,
) where
    M: InterfaceMonitor,
    R: RouteLookup,
{
    let Some(ct) = packet.ct().cloned() else {
        return;
    };
    let info = packet.ct_info().unwrap_or(CtInfo::Established);

    let dst_ip = match &packet.borrow_sliced_packet().net {
        Some(NetSlice::Ipv4(ipv4)) => std::net::IpAddr::V4(ipv4.header().destination_addr()),
        Some(NetSlice::Ipv6(ipv6)) => std::net::IpAddr::V6(ipv6.header().destination_addr()),
        _ => return,
    };

    let Some(out_iface_idx) = routes.route_lookup(dst_ip) else {
        return;
    };

    let Some(out_iface_sys) = interface_monitor.get_by_index(out_iface_idx) else {
        return;
    };

    ct.record_egress_interface(
        packet.ct_direction().unwrap_or(Direction::Original),
        &out_iface_sys.name,
    );

    let raw_mut = unsafe {
        let ptr = packet.borrow_raw().as_ptr() as *mut u8;
        std::slice::from_raw_parts_mut(ptr, packet.borrow_raw().len())
    };

    let _ = engine.postrouting(raw_mut, &ct, info, &out_iface_sys.name, None);
}

pub struct PostSessionHandler<M, R> {
    rx: mpsc::UnboundedReceiver<ReleaseAction>,
    nat_engine: Arc<NatEngine>,
    routes: Arc<R>,
    interface_monitor: Arc<M>,
    tun: Option<Arc<TunForwarder>>,
    disposition_tx: broadcast::Sender<PacketDispositionEvent>,
}

impl<M, R> PostSessionHandler<M, R>
where
    M: InterfaceMonitor + Send + Sync + 'static,
    R: RouteLookup + Send + Sync + 'static,
{
    pub fn new(
        rx: mpsc::UnboundedReceiver<ReleaseAction>,
        nat_engine: Arc<NatEngine>,
        routes: Arc<R>,
        interface_monitor: Arc<M>,
        tun: Option<Arc<TunForwarder>>,
        disposition_tx: broadcast::Sender<PacketDispositionEvent>,
    ) -> Self {
        Self {
            rx,
            nat_engine,
            routes,
            interface_monitor,
            tun,
            disposition_tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<PacketDispositionEvent> {
        self.disposition_tx.subscribe()
    }

    pub async fn run(mut self) {
        while let Some(action) = self.rx.recv().await {
            match action {
                ReleaseAction::Forward { mut packet } => {
                    let direction = packet.ct_direction().unwrap_or(Direction::Original);
                    let dst_port = packet.ct().map(|ct| {
                        let flow = match direction {
                            Direction::Original => ct.original,
                            Direction::Reply => ct.reply(),
                        };

                        flow.dst_port
                    });

                    tracing::trace!(packet_id=?packet.borrow_id(), dst_port=?dst_port, "releasing packet");
                    let packet_id = packet.packet_id();
                    if packet.capture_direction() == CaptureDirection::Egress {
                        tracing::trace!(
                            packet_id=?packet.borrow_id(),
                            dst_port=?dst_port,
                            event = "post_session.forward.egress_skipped",
                            "egress-captured packet already left the router"
                        );
                        let _ = self.disposition_tx.send(PacketDispositionEvent {
                            packet_id,
                            outcome: PacketDispositionOutcome::Forward,
                            drop_reason: None,
                        });
                        continue;
                    }

                    apply_nat_postrouting(
                        &mut packet,
                        &self.nat_engine,
                        self.routes.as_ref(),
                        self.interface_monitor.as_ref(),
                    );
                    let _ = self.disposition_tx.send(PacketDispositionEvent {
                        packet_id,
                        outcome: PacketDispositionOutcome::Forward,
                        drop_reason: None,
                    });
                    if let Some(tun) = &self.tun {
                        tun.forward(&packet).await;
                    }
                }
                ReleaseAction::Drop { packet_id, reason, temp_dst_port } => {
                    tracing::trace!(packet=?packet_id, temp_dst_port=?temp_dst_port, "dropping packet");
                    let _ = self.disposition_tx.send(PacketDispositionEvent {
                        packet_id,
                        outcome: PacketDispositionOutcome::Drop,
                        drop_reason: Some(reason),
                    });
                }
            }
        }
    }
}
