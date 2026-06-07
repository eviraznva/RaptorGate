use std::net::IpAddr;
use std::sync::Arc;

use etherparse::NetSlice;

use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketContext;
use crate::events::{self, Event, EventKind};
use crate::l4::context::SessionContext;
use crate::l4::release::{DropReason, ReleaseAction};
use crate::policy::engine::PolicyEngine;
use crate::policy::policy_evaluator::{DnsEvalContext, PolicyEvalContext};
use crate::data_plane::dns_inspection::dnssec::DnssecProvider;
use crate::rule_tree::types::ArrivalInfo;
use crate::rule_tree::Verdict;
use crate::zones::ZonePairId;

pub fn policy_release_action<ZR, Dns>(
    engine: &PolicyEngine,
    zone_resolver: &ZR,
    zone_pair_id: &ZonePairId,
    packet: PacketContext,
    session: &SessionContext,
    dnssec: Option<&Arc<Dns>>,
) -> ReleaseAction
where
    ZR: crate::zones::resolver::ZoneResolver,
    Dns: DnssecProvider + Send + Sync + 'static,
{
    let arrival = ArrivalInfo::from_time(packet.borrow_arrival_time());

    let dst_ip = match &packet.borrow_sliced_packet().net {
        Some(NetSlice::Ipv4(ipv4)) => IpAddr::V4(ipv4.header().destination_addr()),
        Some(NetSlice::Ipv6(ipv6)) => IpAddr::V6(ipv6.header().destination_addr()),
        _ => return ReleaseAction::Forward { packet },
    };

    let pair = zone_resolver.resolve(packet.borrow_src_interface(), dst_ip);
    let pair_id = pair.as_ref().map(|p| &p.id).unwrap_or(zone_pair_id);

    let dnssec_status = if let Some(provider) = dnssec {
        let is_dns = packet
            .borrow_dpi_ctx()
            .as_ref()
            .is_some_and(|d| d.app_proto == Some(crate::dpi::AppProto::Dns));

        if is_dns {
            let domain = packet
                .borrow_dpi_ctx()
                .as_ref()
                .and_then(|d| d.dns_query_name.clone());
            let qtype = packet.borrow_dpi_ctx().as_ref().and_then(|d| d.dns_query_type);

            if let Some(domain) = domain {
                Some(provider.check_domain(&domain, qtype).status)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    let dns_ctx = dnssec_status.map(|status| DnsEvalContext {
        dnssec_status: Some(status),
    });

    let verdict = engine.evaluate(
        pair_id,
        PolicyEvalContext {
            packet: packet.borrow_sliced_packet(),
            arrival: &arrival,
            dns: dns_ctx.as_ref(),
            dpi: packet.borrow_dpi_ctx().as_ref(),
            identity: packet.borrow_identity_ctx().as_ref(),
            service_dst_port: Some(session.entry().original.dst_port),
        },
    );

    let packet_id = packet.packet_id();
    let temp_dst_port = packet
        .ct()
        .map(|ct| match packet.ct_direction().unwrap_or(Direction::Original) {
            Direction::Original => ct.original.dst_port,
            Direction::Reply => ct.reply().dst_port,
        });

    match verdict {
        Some(Verdict::Allow) | None => ReleaseAction::Forward { packet },
        Some(Verdict::AllowWarn(msg)) => {
            events::emit(Event::new(EventKind::PolicyWarning { message: msg, verdict: "allow" }));
            ReleaseAction::Forward { packet }
        }
        Some(Verdict::Drop) => ReleaseAction::Drop {
            packet_id,
            reason: DropReason::PolicyDenied,
            temp_dst_port,
        },
        Some(Verdict::DropWarn(msg)) => {
            events::emit(Event::new(EventKind::PolicyWarning { message: msg, verdict: "drop" }));
            ReleaseAction::Drop {
                packet_id,
                reason: DropReason::PolicyDenied,
                temp_dst_port,
            }
        }
    }
}

pub fn zone_pair_for_session_packet(session: &SessionContext, dir: Direction) -> &ZonePairId {
    &session.zone_pair_for_packet(dir).id
}
