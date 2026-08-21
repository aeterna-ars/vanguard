use std::{net::SocketAddr, sync::Arc};

use aya::Ebpf;

use tonic::{transport::Server, Request, Response, Status};

use super::vanguard_api::{vanguard_server::*, *};

use vanguard_core::{
    xdp::maps::{
        rules::*,
        stats::*,
        config::*,
    },
    common::{
        commons::{Parse, IpProto, EtherType},
        ip::*,
        maps::{
            blacklist::*,
            whitelist::*,
        }
    }
};
use vanguard_core::brevno::*;
use erret_result::*;

struct VanguardService {
    pub bpf: Arc<Ebpf>,
}

#[tonic::async_trait]
impl Vanguard for VanguardService {
    async fn change_rate_limit(
        &self,
        request: Request<ChangeRateLimitRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        info!("Change rate limit request: {}", req.limit);

        let cfg = XdpConfigMap::read(&mut self.bpf)
            .map_err(|e| Status::internal(format!("read map error: {e}")))?;

        let new = XdpConfig::new(req.limit, cfg.burst_limit);

        XdpConfigMap::write(&mut self.bpf, new)
            .map_err(|e| Status::internal(format!("write map error: {e}")))?;

        Ok(Response::new(()))
    }

    async fn change_burst_limit(
        &self,
        request: Request<ChangeBurstLimitRequest>,
    ) -> Result<(), Status> {
        let req = request.into_inner();
        info!("Change burst limit request: {}", req);

        let cfg = XdpConfigMap::read(&mut bpf)
            .map_err(|e| Status::internal(format!("read map error: {e}")))?;

        let new = XdpConfig {
            rate_limit: cfg.rate_limit,
            block_time: req.time,
        };

        XdpConfigMap::write(&mut bpf, new)
            .map_err(|e| Status::internal(format!("write map error: {e}")))?;

        Ok(Response::new(()))
    }

    async fn change_block_time(
        &self,
        request: Request<ChangeBlockTimeRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        info!("Change block time request: {}", req.time);

        let cfg = XdpConfigMap::read(&mut bpf)
            .map_err(|e| Status::internal(format!("read map error: {e}")))?;

        let new = XdpConfig {
            rate_limit: cfg.rate_limit,
            block_time: req.time,
        };

        XdpConfigMap::write(&mut bpf, new)
            .map_err(|e| Status::internal(format!("write map error: {e}")))?;

        Ok(Response::new(()))
    }

    async fn block(
        &self,
        request: Request<BlockRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        info!("Blacklist request: {}, until {}", req.ip, req.block_until);

        let ip = EbpfNet::to_type(req.ip)
            .map_err(|e| Status::invalid_argument(format!("invalid IP: {e}")))?;

        BlocklistMap::block(&mut bpf, ip)
            .map_err(|e| Status::internal(format!("address block error: {e}")))?;

        Ok(Response::new(()))
    }

    async fn white(
        &self,
        request: Request<WhiteRequest>
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        info!("Whitelist request: {}", req.ip);

        let ip = EbpfNet::to_type(req.ip)
            .map_err(|e| Status::invalid_argument(format!("invalid IP: {e}")))?;

        WhitelistMap::insert(&mut bpf, ip)
            .map_err(|e| Status::internal(format!("insert map error: {e}")))?;

        Ok(Response::new(()))
    }

    async fn add_rule(
        &self,
        request: Request<AddRuleRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let k = req.key;
        let v = req.value;

        if k.is_none() {
            return Err(Status::invalid_argument("no key"))
        }
        let key = k.unwrap();

        if v.is_none() {
            return Err(Status::invalid_argument("no value"))
        }
        let value = v.unwrap();
        let action = value.action;

        let mut redirect: XdpRuleKey = unsafe { core::mem::zeroed() };

        let mut redirect_fmt = String::new();
        if action == "redirect" {
            if let Some(to) = value.redirect {
                redirect_fmt = format!(" -> {}:{} {} {}", to.ip, to.port, to.eth, to.proto);
                redirect = parse_rule_key(to)?;
            } else {
                return Err(Status::invalid_argument("REDIRECT action should have redirect field"));
            }
        }
        
        info!(
            "Add rule request: {}:{} {} -> {}{}",
            key.ip, key.port, key.proto, action, redirect_fmt
        );

        let rule_key = parse_rule_key(key)?;
        
        let rule_value = XdpRuleValue {
            action: XdpRuleAction::to_type(action).map_err(|e| Status::internal(format!("{e}")))?,
            redirect,
        };
        
        RulesMap::add(&mut bpf, rule_key, rule_value).map_err(|e| Status::internal(format!("{e}")))?;
        
        Ok(Response::new(()))
    }

    async fn del_rule(
        &self,
        request: Request<DelRuleRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner().key;

        if req.is_none() {
            return Err(Status::invalid_argument("no key"))
        }
        let key = req.unwrap();
        
        info!(
            "Delete rule request for: {}:{} {} {}",
            key.ip, key.port, key.eth, key.proto
        );

        let rule_key = parse_rule_key(key)?;
        
        RulesMap::remove(&mut bpf, rule_key).map_err(|e| Status::internal(format!("{e}")))?;
        
        Ok(Response::new(()))
    }

    async fn get_stats(
        &self,
        _request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        info!("Get stats request");
        
        let stats = XdpGlobalStatsMap::get_total(&mut bpf)
            .map_err(|_| Status::internal("ebpf map error"))?;

        let response = GetStatsResponse {
            total: stats.total,
            dropped: stats.dropped,
            passed: stats.passed,
            tx: stats.tx,
            redirected: stats.redirected,
        };
        
        Ok(Response::new(response))
    }
}

fn parse_rule_key(key: RuleKey) -> Result<XdpRuleKey, Status> {
    Ok(XdpRuleKey {
        ip: EbpfIp::to_type(key.ip).map_err(|e| Status::invalid_argument(format!("{e}")))?,
        port: EbpfPort(key.port as u16),
        eth: EtherType::to_type(key.eth).map_err(|e| Status::invalid_argument(format!("{e}")))?,
        proto: IpProto::to_type(key.proto).map_err(|e| Status::invalid_argument(format!("{e}")))?,
    })
}

pub async fn init_grpc_server(bpf: Arc<Ebpf>, addr: SocketAddr) -> ErrResult<()> {
    let service = VanguardService {
        bpf,
    };

    info!("gRPC server listening on {}", addr);

    Server::builder()
        .add_service(VanguardServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}

init_global_logger!(1024, 1024, log::LogLevel::Info);