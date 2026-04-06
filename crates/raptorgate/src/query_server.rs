use std::path::Path;
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::data_plane::nat::NatEngine;
use crate::data_plane::tcp_session_tracker::TcpSessionTracker;
use crate::policy::{Policy, PolicyId};
use crate::policy::provider::PolicyManager;
use crate::proto::services::firewall_query_service_server::{
    FirewallQueryService, FirewallQueryServiceServer,
};
use crate::proto::services::{
    GetNatBindingsRequest, GetNatBindingsResponse, GetPoliciesRequest, GetPoliciesResponse, GetPolicyRequest, GetPolicyResponse, GetTcpSessionsRequest, GetTcpSessionsResponse, SwapPoliciesRequest, SwapPoliciesResponse,
    GetZonePairRequest, GetZonePairResponse, GetZonePairsRequest, GetZonePairsResponse, GetZoneRequest, GetZoneResponse, GetZonesRequest, GetZonesResponse, SwapZonePairsRequest, SwapZonePairsResponse, SwapZonesRequest, SwapZonesResponse,
};
use crate::zones::provider::{ZonePairProvider, ZoneProvider};
use crate::zones::{ZoneId, ZoneInterfaceId, ZonePair, ZonePairId};
use crate::zones::Zone;

pub struct QueryServer<PolicySwap> where PolicySwap: PolicyManager + Send + Sync {
    handler: QueryHandler<PolicySwap>,
    socket_path: String,
    shutdown: CancellationToken,
}

impl<PolicySwap> QueryServer<PolicySwap> where PolicySwap: PolicyManager + Send + Sync + 'static {
    pub fn new(
        handler: QueryHandler<PolicySwap>,
        socket_path: impl Into<String>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            handler,
            socket_path: socket_path.into(),
            shutdown,
        }
    }

    pub async fn serve(self) {
        if let Err(e) = prepare_socket(&self.socket_path) {
            tracing::error!(socket = self.socket_path, error = %e, "failed to prepare query socket");
            return;
        }

        let listener = match UnixListener::bind(&self.socket_path) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(socket = self.socket_path, error = %e, "failed to bind query socket");
                return;
            }
        };

        tracing::info!(socket = self.socket_path, "FirewallQueryService listening");

        let incoming = UnixListenerStream::new(listener);

        if let Err(e) = tonic::transport::Server::builder()
            .add_service(FirewallQueryServiceServer::new(self.handler))
            .serve_with_incoming_shutdown(incoming, self.shutdown.cancelled())
            .await
        {
            tracing::error!(error = %e, "FirewallQueryService server error");
        }

        cleanup_socket(&self.socket_path);
    }
}

#[derive(Clone)]
pub struct QueryHandler<PolicySwap> where PolicySwap: PolicyManager {
    pub tcp_tracker: Arc<TcpSessionTracker>,
    pub nat_engine: Arc<Mutex<NatEngine>>,
    pub policy_store: Arc<PolicySwap>,
    pub zone_store: Arc<ZoneProvider>,
    pub zone_pair_store: Arc<ZonePairProvider>,
}

#[tonic::async_trait]
impl<Swapper> FirewallQueryService for QueryHandler<Swapper> where Swapper: PolicyManager + Send + Sync + 'static {
    async fn get_tcp_sessions(
        &self,
        _request: Request<GetTcpSessionsRequest>,
    ) -> Result<Response<GetTcpSessionsResponse>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }

    async fn swap_policies(
        &self,
        request: Request<SwapPoliciesRequest>
    ) -> Result<Response<SwapPoliciesResponse>, Status> {
        let rules = request.into_inner().rules;
        let mut policies = Vec::with_capacity(rules.len());

        for rule in rules {
            match Policy::try_from_rule(rule) {
                Ok(policy) => policies.push(policy),
                Err(err) => {
                    tracing::warn!(error = %err, "failed to parse policy from SwapPoliciesRequest");
                    return Err(Status::invalid_argument(format!("failed to parse policy: {err}")));
                }
            }
        }
        
        let response = match self.policy_store.swap_policies(policies).await {
            Ok(()) => SwapPoliciesResponse { },
            Err(err) => {
                tracing::error!(error = %err, "failed to swap policies");
                return Err(Status::internal(format!("failed to swap policies: {err}")));
            }
        };

        Ok(Response::new(response))
    }

    async fn get_policies(
        &self,
        _request: Request<GetPoliciesRequest>
    ) -> Result<Response<GetPoliciesResponse>, Status> {
        let rules = self.policy_store.get_policies()
            .iter()
            .map(|(id, pol)| pol.clone().into_rule(id.clone()))
            .collect::<Vec<_>>();

        Ok(Response::new(GetPoliciesResponse {
            rules,
        }))
    }

    async fn get_policy(
        &self,
        request: Request<GetPolicyRequest>,
    ) -> Result<Response<GetPolicyResponse>, Status> {
        let id: PolicyId = Uuid::try_parse(&request.into_inner().id)
            .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?
            .into();
        match self.policy_store.get_policy(&id) {
            Some(policy) => Ok(Response::new(GetPolicyResponse {
                rule: Some(policy.into_rule(id)),
            })),
            None => Err(Status::not_found(format!("policy with id {id} not found"))),
        }
    }

    async fn get_nat_bindings(
        &self,
        _request: Request<GetNatBindingsRequest>,
    ) -> Result<Response<GetNatBindingsResponse>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }

    async fn swap_zones(
        &self,
        request: Request<SwapZonesRequest>,
    ) -> Result<Response<SwapZonesResponse>, Status> {
        let zones = request.into_inner().zones;
        let mut zones_domain = Vec::with_capacity(zones.len());

        for zone in zones {
            match Zone::try_from_proto(zone) {
                Ok(pair) => zones_domain.push(pair),
                Err(err) => {
                    tracing::warn!(error = %err, "failed to parse zone from SwapZonesRequest");
                    return Err(Status::invalid_argument(format!("failed to parse zone: {err}")));
                }
            }
        }
        
        let response = match self.zone_store.swap_zones(zones_domain).await {
            Ok(()) => SwapZonesResponse { },
            Err(err) => {
                tracing::error!(error = %err, "failed to swap zones");
                return Err(Status::internal(format!("failed to swap zones: {err}")));
            }
        };

        Ok(Response::new(response))
    }

    async fn get_zones(
        &self,
        _request: Request<GetZonesRequest>
    ) -> Result<Response<GetZonesResponse>, Status> {
        let zones = self.zone_store.get_zones()
            .iter()
            .map(|(id, pol)| pol.clone().into_proto(id.clone()))
            .collect::<Vec<_>>();

        Ok(Response::new(GetZonesResponse {
            zones,
        }))
    }

    async fn get_zone(
        &self,
        request: Request<GetZoneRequest>,
    ) -> Result<Response<GetZoneResponse>, Status> {
        let id = Uuid::try_parse(&request.into_inner().id)
            .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?
            .into();
        match self.zone_store.get_zone(&id) {
            Some(policy) => Ok(Response::new(GetZoneResponse {
                zone: Some(policy.into_proto(id)),
            })),
            None => Err(Status::not_found(format!("policy with id {id} not found"))),
        }
    }

    async fn swap_zone_pairs(
        &self,
        request: Request<SwapZonePairsRequest>,
    ) -> Result<Response<SwapZonePairsResponse>, Status> {
        let zone_pairs = request.into_inner().zone_pairs;
        let mut zone_pairs_domain = Vec::with_capacity(zone_pairs.len());

        for zp in zone_pairs {
            match ZonePair::try_from_proto(zp) {
                Ok(pair) => zone_pairs_domain.push(pair),
                Err(err) => {
                    tracing::warn!(error = %err, "failed to parse zone pair from SwapZonePairsRequest");
                    return Err(Status::invalid_argument(format!("failed to parse zone pair: {err}")));
                }
            }
        }

        let response = match self.zone_pair_store.swap_zone_pairs(zone_pairs_domain).await {
            Ok(()) => SwapZonePairsResponse {},
            Err(err) => {
                tracing::error!(error = %err, "failed to swap zone pairs");
                return Err(Status::internal(format!("failed to swap zone pairs: {err}")));
            }
        };

        Ok(Response::new(response))
    }

    async fn get_zone_pairs(
        &self,
        _request: Request<GetZonePairsRequest>,
    ) -> Result<Response<GetZonePairsResponse>, Status> {
        let zone_pairs = self.zone_pair_store.get_zone_pairs()
            .iter()
            .map(|(id, pair)| pair.clone().into_proto(id.clone()))
            .collect::<Vec<_>>();

        Ok(Response::new(GetZonePairsResponse {
            zone_pairs,
        }))
    }

    async fn get_zone_pair(
        &self,
        request: Request<GetZonePairRequest>,
    ) -> Result<Response<GetZonePairResponse>, Status> {
        let id = Uuid::try_parse(&request.into_inner().id)
            .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?
            .into();
        match self.zone_pair_store.get_zone_pair(&id) {
            Some(pair) => Ok(Response::new(GetZonePairResponse {
                zone_pair: Some(pair.into_proto(id)),
            })),
            None => Err(Status::not_found(format!("zone pair with id {id} not found"))),
        }
    }
}

fn prepare_socket(socket_path: &str) -> std::io::Result<()> {
    let path = Path::new(socket_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    Ok(())
}

fn cleanup_socket(socket_path: &str) {
    if let Err(e) = std::fs::remove_file(socket_path)
        && e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(socket = socket_path, error = %e, "failed to remove query socket");
        }
}
