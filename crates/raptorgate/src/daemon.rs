#![allow(dead_code)]

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use etherparse::NetSlice;
use parking_lot::Mutex;
use tokio::sync::{broadcast, mpsc};

use crate::conntrack::helper::HelperRegistry;
use crate::conntrack::session_manager::SessionManager;
use crate::conntrack::table::Conntrack;
use crate::post_session::PostSessionHandler;
use crate::config::provider::{AppConfigProvider, AppConfigStore};
use crate::config::AppConfig;
use crate::data_plane::dns_inspection::dns_inspection::DnsInspection;
use crate::data_plane::dns_inspection::dnssec::DnssecProvider;
use crate::data_plane::interface_sniffer::RawPacket;
use crate::data_plane::packet_context::CaptureDirection;
use crate::data_plane::ips::ips::Ips;
use crate::disk_store::SingleDiskStore;
use crate::dpi::smtp::SmtpTracker;
use crate::dpi::smtp::smtp_policy_retriever::SmtpPolicyRetriever;
use crate::dpi::DpiClassifier;
use crate::identity::IdentitySessionStore;
use crate::interfaces::{InterfaceMonitor, NetworkInterfaceMonitor};
use crate::ip_defrag::IpDefragEngine;
use crate::l4::{IcmpL4PipelineFactory, TcpL4PipelineFactory, UdpL4PipelineFactory};
use crate::metrics::MetricsCollector;
use crate::ml::{FlowStatsAggregator, MlPacketInspector};
use crate::nat::NatEngine;
use crate::netlink::routing_table::{RouteLookup, RoutingTable};
use crate::pipeline::wrappers::{
    ConntrackConfirmStage, ConntrackInStage, DnsBlockListStage, DnsEchMitigationStage,
    DnsTunnelingStage, DpiStage, FtpAlgStage, IdentityLookupStage, IpsStage, L4StateStage,
    LocalOwnershipStage, MetricsStage, MlAlertStage, NatPostroutingStage, NatPreroutingStage,
    PolicyEvalStage, SessionHandoffStage, SmtpStage, TlsPortEnforcementStage, ValidationStage,
};
use crate::pipeline::{
    Chain, ExecutionItem, ExecutionReceiver, ExecutionSender, ExecutionStage, Stage, StageOutcome,
};
use crate::policy::engine::PolicyEngine;
use crate::tls::TlsDecisionEngine;
use crate::tls::l4_inspection::TlsL4InspectionConfig;
use crate::zones::provider::ZoneInterfaceProvider;
use crate::zones::resolver::RoutingZoneResolver;

pub struct StaticDeps<'a, D: DaemonDeps + ?Sized> {
    pub metrics_collector: &'a Arc<MetricsCollector>,
    pub config_provider: &'a Arc<AppConfigProvider<D::ConfigStore>>,
    pub zone_interfaces: &'a Arc<ZoneInterfaceProvider>,
    pub local_ips: &'a Arc<HashSet<IpAddr>>,
    pub identity_sessions: &'a Arc<IdentitySessionStore>,
    pub conntrack: &'a Arc<Conntrack>,
    pub dpi_classifier: &'a Arc<DpiClassifier>,
    pub ml_flow_stats: &'a Arc<FlowStatsAggregator>,
    pub decision_engine: &'a Arc<TlsDecisionEngine>,
    pub dns_inspection: &'a Arc<DnsInspection>,
    pub policy_dnssec: &'a Arc<D::Dnssec>,
    pub ips: &'a Arc<Ips>,
    pub nat_engine: &'a Arc<NatEngine>,
    pub ml_detector: &'a Arc<dyn MlPacketInspector>,
    pub policy_engine: &'a Arc<PolicyEngine>,
    pub zone_resolver: &'a Arc<RoutingZoneResolver<D::IfaceMon>>,
    pub routing_table: &'a Arc<D::Routes>,
    pub interface_monitor: &'a Arc<D::IfaceMon>,
    pub helpers: &'a Arc<HelperRegistry>,
    pub smtp_tracker: &'a Arc<SmtpTracker>,
    pub smtp_policy_retriever: &'a Arc<SmtpPolicyRetriever<RoutingZoneResolver<D::IfaceMon>>>,
    pub tls_l4_inspection: &'a Option<Arc<TlsL4InspectionConfig>>,
}

pub trait DaemonDeps: Send + Sync + 'static {
    type ConfigStore: AppConfigStore;
    type IfaceMon: InterfaceMonitor;
    type Routes: RouteLookup;
    type Dnssec: DnssecProvider + Send + Sync + 'static;

    fn static_dependencies(&self) -> StaticDeps<'_, Self>;
}

pub struct ProdDeps {
    pub metrics_collector: Arc<MetricsCollector>,
    pub config_provider: Arc<AppConfigProvider<SingleDiskStore<AppConfig>>>,
    pub zone_interfaces: Arc<ZoneInterfaceProvider>,
    pub local_ips: Arc<HashSet<IpAddr>>,
    pub identity_sessions: Arc<IdentitySessionStore>,
    pub conntrack: Arc<Conntrack>,
    pub dpi_classifier: Arc<DpiClassifier>,
    pub ml_flow_stats: Arc<FlowStatsAggregator>,
    pub decision_engine: Arc<TlsDecisionEngine>,
    pub dns_inspection: Arc<DnsInspection>,
    pub ips: Arc<Ips>,
    pub nat_engine: Arc<NatEngine>,
    pub ml_detector: Arc<dyn MlPacketInspector>,
    pub policy_engine: Arc<PolicyEngine>,
    pub zone_resolver: Arc<RoutingZoneResolver<NetworkInterfaceMonitor>>,
    pub routing_table: Arc<RoutingTable>,
    pub interface_monitor: Arc<NetworkInterfaceMonitor>,
    pub helpers: Arc<HelperRegistry>,
    pub smtp_tracker: Arc<SmtpTracker>,
    pub smtp_policy_retriever: Arc<SmtpPolicyRetriever<RoutingZoneResolver<NetworkInterfaceMonitor>>>,
    pub tls_l4_inspection: Option<Arc<TlsL4InspectionConfig>>,
}

impl DaemonDeps for ProdDeps {
    type ConfigStore = SingleDiskStore<AppConfig>;
    type IfaceMon = NetworkInterfaceMonitor;
    type Routes = RoutingTable;
    type Dnssec = DnsInspection;

    fn static_dependencies(&self) -> StaticDeps<'_, Self> {
        StaticDeps {
            metrics_collector: &self.metrics_collector,
            config_provider: &self.config_provider,
            zone_interfaces: &self.zone_interfaces,
            local_ips: &self.local_ips,
            identity_sessions: &self.identity_sessions,
            conntrack: &self.conntrack,
            dpi_classifier: &self.dpi_classifier,
            ml_flow_stats: &self.ml_flow_stats,
            decision_engine: &self.decision_engine,
            dns_inspection: &self.dns_inspection,
            policy_dnssec: &self.dns_inspection,
            ips: &self.ips,
            nat_engine: &self.nat_engine,
            ml_detector: &self.ml_detector,
            policy_engine: &self.policy_engine,
            zone_resolver: &self.zone_resolver,
            routing_table: &self.routing_table,
            interface_monitor: &self.interface_monitor,
            helpers: &self.helpers,
            smtp_tracker: &self.smtp_tracker,
            smtp_policy_retriever: &self.smtp_policy_retriever,
            tls_l4_inspection: &self.tls_l4_inspection,
        }
    }
}

pub type DataPipeline<D> = Chain<
    ValidationStage,
    Chain<
        MetricsStage,
        Chain<
            LocalOwnershipStage<<D as DaemonDeps>::ConfigStore>,
            Chain<
                IdentityLookupStage,
                Chain<
                    ConntrackInStage,
                    Chain<
                        DpiStage,
                        Chain<
                            TlsPortEnforcementStage<<D as DaemonDeps>::ConfigStore>,
                            Chain<
                                DnsBlockListStage,
                                Chain<
                                    DnsTunnelingStage,
                                    Chain<
                                        DnsEchMitigationStage,
                                        Chain<
                                            IpsStage,
                                            Chain<
                                                NatPreroutingStage,
                                                Chain<
                                                    L4StateStage,
                                                    Chain<
                                                        MlAlertStage,
                                                        Chain<
                                                            PolicyEvalStage<
                                                                RoutingZoneResolver<
                                                                    <D as DaemonDeps>::IfaceMon,
                                                                >,
                                                                <D as DaemonDeps>::Dnssec,
                                                            >,
                                                            Chain<
                                                                NatPostroutingStage<
                                                                    <D as DaemonDeps>::IfaceMon,
                                                                    <D as DaemonDeps>::Routes,
                                                                >,
                                                                Chain<
                                                                    FtpAlgStage,
                                                                    Chain<
                                                                        SmtpStage,
                                                                        Chain<
                                                                            ConntrackConfirmStage,
                                                                            ExecutionStage,
                                                                        >,
                                                                    >,
                                                                >,
                                                            >,
                                                        >,
                                                    >,
                                                >,
                                            >,
                                        >,
                                    >,
                                >,
                            >,
                        >,
                    >,
                >,
            >,
        >,
    >,
>;

pub type SessionsFor<D> = SessionManager<
    RoutingZoneResolver<<D as DaemonDeps>::IfaceMon>,
    <D as DaemonDeps>::Dnssec,
>;

pub type V2Pipeline<D> = Chain<
    ValidationStage,
    Chain<
        MetricsStage,
        Chain<
            LocalOwnershipStage<<D as DaemonDeps>::ConfigStore>,
            Chain<
                IdentityLookupStage,
                Chain<
                    ConntrackInStage,
                    Chain<
                        NatPreroutingStage,
                        Chain<
                            NatPostroutingStage<
                                <D as DaemonDeps>::IfaceMon,
                                <D as DaemonDeps>::Routes,
                            >,
                            Chain<
                                ConntrackConfirmStage,
                                SessionHandoffStage<
                                    RoutingZoneResolver<<D as DaemonDeps>::IfaceMon>,
                                    <D as DaemonDeps>::Dnssec,
                                >,
                            >,
                        >,
                    >,
                >,
            >,
        >,
    >,
>;

fn build_v2_pipeline<D: DaemonDeps<IfaceMon = NetworkInterfaceMonitor>>(
    deps: &StaticDeps<D>,
    sessions: Arc<SessionsFor<D>>,
) -> V2Pipeline<D>
where
    RoutingZoneResolver<D::IfaceMon>: Clone,
    D::Dnssec: DnssecProvider + Send + Sync + 'static,
{
    V2Pipeline::<D> {
        head: ValidationStage,
        tail: Chain {
            head: MetricsStage {
                collector: Arc::clone(deps.metrics_collector),
            },
            tail: Chain {
                head: LocalOwnershipStage {
                    config_provider: Arc::clone(deps.config_provider),
                    zone_interface_provider: Arc::clone(deps.zone_interfaces),
                    local_ips: Arc::clone(deps.local_ips),
                    conntrack: Arc::clone(deps.conntrack),
                },
                tail: Chain {
                    head: IdentityLookupStage {
                        store: Arc::clone(deps.identity_sessions),
                    },
                    tail: Chain {
                        head: ConntrackInStage {
                            ct: Arc::clone(deps.conntrack),
                        },
                        tail: Chain {
                            head: NatPreroutingStage {
                                engine: Arc::clone(deps.nat_engine),
                                zone_interface_provider: Arc::clone(deps.zone_interfaces),
                            },
                            tail: Chain {
                                head: NatPostroutingStage {
                                    engine: Arc::clone(deps.nat_engine),
                                    routes: Arc::clone(deps.routing_table),
                                    interface_monitor: Arc::clone(deps.interface_monitor),
                                    zone_interface_provider: Arc::clone(deps.zone_interfaces),
                                },
                                tail: Chain {
                                    head: ConntrackConfirmStage {
                                        ct: Arc::clone(deps.conntrack),
                                    },
                                    tail: SessionHandoffStage {
                                        sessions,
                                        ct: Arc::clone(deps.conntrack),
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    }
}

fn build_pipeline<D: DaemonDeps<IfaceMon = NetworkInterfaceMonitor>>(deps: &Arc<D>, exec_tx: &ExecutionSender) -> DataPipeline<D> {
    let s = deps.static_dependencies();
    DataPipeline::<D> {
        head: ValidationStage,
        tail: Chain {
            head: MetricsStage {
                collector: Arc::clone(s.metrics_collector),
            },
            tail: Chain {
                head: LocalOwnershipStage {
                    config_provider: Arc::clone(s.config_provider),
                    zone_interface_provider: Arc::clone(s.zone_interfaces),
                    local_ips: Arc::clone(s.local_ips),
                    conntrack: Arc::clone(s.conntrack),
                },
                tail: Chain {
                    head: IdentityLookupStage {
                        store: Arc::clone(s.identity_sessions),
                    },
                    tail: Chain {
                        head: ConntrackInStage {
                            ct: Arc::clone(s.conntrack),
                        },
                        tail: Chain {
                            head: DpiStage {
                                classifier: Arc::clone(s.dpi_classifier),
                                flow_stats: Arc::clone(s.ml_flow_stats),
                                pinning_detector: Some(s.decision_engine.pinning_detector_arc()),
                            },
                            tail: Chain {
                                head: TlsPortEnforcementStage {
                                    config_provider: Arc::clone(s.config_provider),
                                },
                                tail: Chain {
                                    head: DnsBlockListStage {
                                        inspection: Arc::clone(s.dns_inspection),
                                    },
                                    tail: Chain {
                                        head: DnsTunnelingStage {
                                            inspection: Arc::clone(s.dns_inspection),
                                        },
                                        tail: Chain {
                                            head: DnsEchMitigationStage {
                                                inspection: Arc::clone(s.dns_inspection),
                                            },
                                            tail: Chain {
                                                head: IpsStage {
                                                    inspection: Arc::clone(s.ips),
                                                },
                                                tail: Chain {
                                                    head: NatPreroutingStage {
                                                        engine: Arc::clone(s.nat_engine),
                                                        zone_interface_provider: Arc::clone(s.zone_interfaces),
                                                    },
                                                    tail: Chain {
                                                        head: L4StateStage {
                                                            flow_stats: Arc::clone(s.ml_flow_stats),
                                                        },
                                                        tail: Chain {
                                                            head: MlAlertStage::new(Arc::clone(s.ml_detector)),
                                                            tail: Chain {
                                                                head: PolicyEvalStage {
                                                                    policy_engine: Arc::clone(s.policy_engine),
                                                                    zone_resolver: Arc::clone(s.zone_resolver),
                                                                    dnssec: Some(Arc::clone(s.policy_dnssec)),
                                                                },
                                                                tail: Chain {
                                                                    head: NatPostroutingStage {
                                                                        engine: Arc::clone(s.nat_engine),
                                                                        routes: Arc::clone(s.routing_table),
                                                                        interface_monitor: Arc::clone(s.interface_monitor),
                                                                        zone_interface_provider: Arc::clone(s.zone_interfaces),
                                                                    },
                                                                    tail: Chain {
                                                                        head: FtpAlgStage {
                                                                            conntrack: Arc::clone(s.conntrack),
                                                                            helpers: Arc::clone(s.helpers),
                                                                        },
                                                                        tail: Chain {
                                                                            head: SmtpStage {
                                                                                tracker: Arc::clone(s.smtp_tracker),
                                                                            },
                                                                            tail: Chain {
                                                                                head: ConntrackConfirmStage {
                                                                                    ct: Arc::clone(s.conntrack),
                                                                                },
                                                                                tail: ExecutionStage {
                                                                                    tx: exec_tx.clone(),
                                                                                },
                                                                            },
                                                                        },
                                                                    },
                                                                },
                                                            },
                                                        },
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    }
}

pub struct Daemon<D: DaemonDeps> {
    deps: Arc<D>,
    pipeline: DataPipeline<D>,
    defrag: IpDefragEngine,
    exec_tx: ExecutionSender,
    test_exec_rx: Mutex<Option<ExecutionReceiver>>,
}

#[derive(Debug)]
pub struct ProcessOutput {
    pub emitted: Vec<ExecutionItem>,
    pub stage_outcome: Option<StageOutcome>,
}

#[derive(Debug)]
pub struct ProcessOutputWithPacketId {
    pub packet_id: Option<crate::data_plane::packet_context::PacketId>,
    pub output: ProcessOutput,
}

impl<D: DaemonDeps<IfaceMon = NetworkInterfaceMonitor>> Daemon<D> {
    pub fn assemble(
        deps: Arc<D>,
        defrag: IpDefragEngine,
        exec_tx: ExecutionSender,
        test_exec_rx: Option<ExecutionReceiver>,
    ) -> Self {
        let pipeline = build_pipeline(&deps, &exec_tx);
        Self {
            deps,
            pipeline,
            defrag,
            exec_tx,
            test_exec_rx: Mutex::new(test_exec_rx),
        }
    }

    pub fn deps(&self) -> &Arc<D> {
        &self.deps
    }

    pub fn pipeline(&self) -> &DataPipeline<D> {
        &self.pipeline
    }

    pub fn pipeline_clone(&self) -> DataPipeline<D> {
        self.pipeline.clone()
    }

    pub fn exec_sender(&self) -> ExecutionSender {
        self.exec_tx.clone()
    }

    pub fn defrag(&self) -> &IpDefragEngine {
        &self.defrag
    }

    pub async fn process_raw(&self, raw: Vec<u8>, iface: Arc<str>) -> ProcessOutput {
        let packet = RawPacket { raw, iface, capture_direction: CaptureDirection::Ingress };
        let Some(mut ctx) = self.defrag.process_raw(packet) else {
            return ProcessOutput {
                emitted: Vec::new(),
                stage_outcome: None,
            };
        };

        if !matches!(
            &ctx.borrow_sliced_packet().net,
            Some(NetSlice::Ipv4(_) | NetSlice::Ipv6(_))
        ) {
            return ProcessOutput {
                emitted: Vec::new(),
                stage_outcome: None,
            };
        }

        let stage_outcome = self.pipeline.process(&mut ctx, &self.exec_tx).await;

        let mut emitted = Vec::new();
        if let Some(rx) = self.test_exec_rx.lock().as_mut() {
            while let Ok(item) = rx.try_recv() {
                emitted.push(item);
            }
        }

        ProcessOutput {
            emitted,
            stage_outcome: Some(stage_outcome),
        }
    }
}

pub struct DaemonV2<D: DaemonDeps> {
    deps: Arc<D>,
    pipeline: V2Pipeline<D>,
    defrag: IpDefragEngine,
    test_exec_rx: Mutex<Option<ExecutionReceiver>>,
    sessions: Arc<SessionsFor<D>>,
    disposition_tx: broadcast::Sender<crate::l4::release::PacketDispositionEvent>,
    release_tx: mpsc::UnboundedSender<crate::l4::release::ReleaseAction>,
}

impl<D: DaemonDeps<IfaceMon = NetworkInterfaceMonitor>> DaemonV2<D>
where
    RoutingZoneResolver<D::IfaceMon>: Clone,
    D::Dnssec: DnssecProvider + Send + Sync + 'static,
{
    pub fn assemble_v2(
        deps: Arc<D>,
        defrag: IpDefragEngine,
        _exec_tx: ExecutionSender,
        test_exec_rx: Option<ExecutionReceiver>,
        tun: Option<Arc<crate::data_plane::tun_forwarder::TunForwarder>>,
    ) -> Arc<Self> {
        let s = deps.static_dependencies();
        let (release_tx, release_rx) = tokio::sync::mpsc::unbounded_channel();
        let (disposition_tx, _) = broadcast::channel(1024);
        let sessions = SessionManager::new(
            Arc::clone(s.conntrack),
            TcpL4PipelineFactory::new_application_router(
                Arc::clone(s.smtp_policy_retriever),
                s.tls_l4_inspection.as_ref().map(Arc::clone),
            ),
            UdpL4PipelineFactory::default(),
            IcmpL4PipelineFactory::default(),
            Arc::clone(s.policy_engine),
            s.zone_resolver.as_ref().clone(),
            Some(Arc::clone(s.policy_dnssec)),
            Some(Arc::clone(s.dpi_classifier)),
            Some(Arc::clone(s.dns_inspection)),
            Some(Arc::clone(s.ips)),
            Some(MlAlertStage::new(Arc::clone(s.ml_detector))),
            Some(Arc::clone(s.ml_flow_stats)),
            Some(FtpAlgStage {
                conntrack: Arc::clone(s.conntrack),
                helpers: Arc::clone(s.helpers),
            }),
            release_tx.clone(),
        );
        let pipeline = build_v2_pipeline(&s, Arc::clone(&sessions));
        let post_session = PostSessionHandler::new(
            release_rx,
            Arc::clone(s.nat_engine),
            Arc::clone(s.routing_table),
            Arc::clone(s.interface_monitor),
            Arc::clone(s.zone_interfaces),
            tun,
            disposition_tx.clone(),
        );
        tokio::spawn(post_session.run());
        Arc::new(Self {
            deps,
            pipeline,
            defrag,
            test_exec_rx: Mutex::new(test_exec_rx),
            sessions,
            disposition_tx,
            release_tx,
        })
    }

    pub fn deps(&self) -> &Arc<D> {
        &self.deps
    }

    pub fn sessions(&self) -> &Arc<SessionsFor<D>> {
        &self.sessions
    }

    pub fn subscribe_packet_dispositions(&self) -> broadcast::Receiver<crate::l4::release::PacketDispositionEvent> {
        self.disposition_tx.subscribe()
    }

    pub fn defrag(&self) -> &IpDefragEngine {
        &self.defrag
    }

    pub fn pipeline_clone(&self) -> V2Pipeline<D> {
        self.pipeline.clone()
    }

    pub async fn process_raw(&self, raw: Vec<u8>, iface: Arc<str>) -> ProcessOutput {
        self.process_raw_with_packet_id(raw, iface).await.output
    }

    pub async fn process_raw_with_packet_id(
        &self,
        raw: Vec<u8>,
        iface: Arc<str>,
    ) -> ProcessOutputWithPacketId {
        let packet = RawPacket { raw, iface, capture_direction: CaptureDirection::Ingress };
        let Some(mut ctx) = self.defrag.process_raw(packet) else {
            return ProcessOutputWithPacketId {
                packet_id: None,
                output: ProcessOutput {
                    emitted: Vec::new(),
                    stage_outcome: None,
                },
            };
        };

        let packet_id = Some(ctx.packet_id());

        if !matches!(
            &ctx.borrow_sliced_packet().net,
            Some(NetSlice::Ipv4(_) | NetSlice::Ipv6(_))
        ) {
            return ProcessOutputWithPacketId {
                packet_id,
                output: ProcessOutput {
                    emitted: Vec::new(),
                    stage_outcome: None,
                },
            };
        }

        let (exec_tx, _) = mpsc::unbounded_channel();
        let stage_outcome = self.pipeline.process(&mut ctx, &exec_tx).await;

        let mut emitted = Vec::new();
        if let Some(rx) = self.test_exec_rx.lock().as_mut() {
            while let Ok(item) = rx.try_recv() {
                emitted.push(item);
            }
        }

        ProcessOutputWithPacketId {
            packet_id,
            output: ProcessOutput {
                emitted,
                stage_outcome: Some(stage_outcome),
            },
        }
    }
}
