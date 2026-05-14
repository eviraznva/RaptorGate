use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketContext;

use super::noop::{NoopIcmpStage, NoopTcpStage, NoopUdpStage};
use super::stage::L4Outcome;

pub type TcpNoopPipeline = NoopTcpStage;
pub type UdpNoopPipeline = NoopUdpStage;
pub type IcmpNoopPipeline = NoopIcmpStage;

#[derive(Debug, Default, Clone, Copy)]
pub struct TcpL4PipelineFactory;

impl TcpL4PipelineFactory {
    pub fn build(&self) -> TcpNoopPipeline {
        NoopTcpStage::default()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UdpL4PipelineFactory;

impl UdpL4PipelineFactory {
    pub fn build(&self) -> UdpNoopPipeline {
        NoopUdpStage::default()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct IcmpL4PipelineFactory;

impl IcmpL4PipelineFactory {
    pub fn build(&self) -> IcmpNoopPipeline {
        NoopIcmpStage::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::stage::L4Stage;
    use etherparse::PacketBuilder;
    use std::sync::Arc;

    fn sample_packet() -> PacketContext {
        let mut raw = Vec::new();
        PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(12345, 80, 1, 65535)
            .write(&mut raw, b"x")
            .expect("packet");
        PacketContext::from_raw(raw, Arc::from("eth0")).expect("packet")
    }

    #[test]
    fn tcp_factory_pipeline_forwards() {
        let mut pipe = TcpL4PipelineFactory::default().build();
        let mut ctx = ();
        let mut pkt = sample_packet();
        let o = pipe.on_packet(&mut ctx, &mut pkt, Direction::Original);
        assert_eq!(o, L4Outcome::Forward);
    }

    #[test]
    fn udp_factory_pipeline_forwards() {
        let mut pipe = UdpL4PipelineFactory::default().build();
        let mut ctx = ();
        let mut pkt = sample_packet();
        let o = pipe.on_packet(&mut ctx, &mut pkt, Direction::Original);
        assert_eq!(o, L4Outcome::Forward);
    }

    #[test]
    fn icmp_factory_pipeline_forwards() {
        let mut pipe = IcmpL4PipelineFactory::default().build();
        let mut ctx = ();
        let mut pkt = sample_packet();
        let o = pipe.on_packet(&mut ctx, &mut pkt, Direction::Original);
        assert_eq!(o, L4Outcome::Forward);
    }
}
