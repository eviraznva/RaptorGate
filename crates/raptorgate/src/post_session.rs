use std::sync::Arc;

use etherparse::NetSlice;
use tokio::sync::mpsc;

use crate::conntrack::entry::CtInfo;
use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketContext;
use crate::data_plane::tun_forwarder::TunForwarder;
use crate::interfaces::InterfaceMonitor;
use crate::l4::release::ReleaseAction;
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

pub struct PostSessionPipeline<M, R> {
    rx: mpsc::UnboundedReceiver<ReleaseAction>,
    nat_engine: Arc<NatEngine>,
    routes: Arc<R>,
    interface_monitor: Arc<M>,
    tun: Option<Arc<TunForwarder>>,
}

impl<M, R> PostSessionPipeline<M, R>
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
    ) -> Self {
        Self {
            rx,
            nat_engine,
            routes,
            interface_monitor,
            tun,
        }
    }

    pub async fn run(mut self) {
        while let Some(action) = self.rx.recv().await {
            match action {
                ReleaseAction::Forward { mut packet } => {
                    apply_nat_postrouting(
                        &mut packet,
                        &self.nat_engine,
                        self.routes.as_ref(),
                        self.interface_monitor.as_ref(),
                    );
                    if let Some(tun) = &self.tun {
                        tun.forward(&packet).await;
                    }
                }
                ReleaseAction::Drop { packet_id: _, reason: _ } => {}
            }
        }
    }
}
