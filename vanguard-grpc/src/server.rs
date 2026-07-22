use std::{net::SocketAddr, sync::Arc};

use tokio::sync::Mutex;

use aya::Ebpf;

use tonic::{transport::Server, Request, Response, Status};

use crate::vanguard_api::{self, vanguard_server::*, *};

use vanguard_common::{
    erret_result::*,
    maps::{
        self,
        GlobalStats,
        RuleAction
    },
    parse::*,
    brevno::*,
};

struct VanguardService {
    pub bpf: Arc<Mutex<Ebpf>>,
}

#[tonic::async_trait]
impl Vanguard for VanguardService {
    async fn change_rate_limit(
        &self,
        request: Request<ChangeRateLimitRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        info!("Change rate limit request: {}", req.limit);

        let mut bpf = self.bpf.lock().await;

        let cfg = maps::ConfigMap::read(&mut bpf)
            .map_err(|e| Status::internal(format!("read map error: {e}")))?;

        let new = maps::Config {
            rate_limit: req.limit,
            block_time: cfg.block_time
        };

        maps::ConfigMap::write(&mut bpf, new)
            .map_err(|e| Status::internal(format!("write map error: {e}")))?;

        Ok(Response::new(()))
    }

    async fn change_block_time(
        &self,
        request: Request<ChangeBlockTimeRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        info!("Change block time request: {}", req.time);

        let mut bpf = self.bpf.lock().await;

        let cfg = maps::ConfigMap::read(&mut bpf)
            .map_err(|e| Status::internal(format!("read map error: {e}")))?;

        let new = maps::Config {
            rate_limit: cfg.rate_limit,
            block_time: req.time,
        };

        maps::ConfigMap::write(&mut bpf, new)
            .map_err(|e| Status::internal(format!("write map error: {e}")))?;

        Ok(Response::new(()))
    }

    async fn block(
        &self,
        request: Request<BlockRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        info!("Blocklist request: {}, until {}", req.ip, req.block_until);

        let ip = parse_ip(req.ip)
            .map_err(|e| Status::invalid_argument(format!("Incorrect IP: {e}")))?.0;

        let mut bpf = self.bpf.lock().await;

        maps::BlocklistMap::block(&mut bpf, ip, req.block_until)
            .map_err(|e| Status::internal(format!("address block error: {e}")))?;

        Ok(Response::new(()))
    }

    async fn white(
        &self,
        request: Request<WhiteRequest>
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        info!("Whitelist request: {}", req.ip);

        let ip = parse_ip(req.ip)
            .map_err(|e| Status::invalid_argument(format!("Incorrect IP: {e}")))?.0;

        let mut bpf = self.bpf.lock().await;

        maps::WhitelistMap::insert(&mut bpf, ip)
            .map_err(|e| Status::internal(format!("insert map error: {e}")))?;

        Ok(Response::new(()))
    }

    async fn add_rule(
        &self,
        request: Request<AddRuleRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner().rule.unwrap();
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

        let mut redirect_kotakbas: Option<vanguard_common::maps::RuleKey> = None;

        let mut redirect_fmt = String::new();
        if value.redirect_to.is_some() {
            let redirect_to = Some(value.redirect_to.unwrap());
            redirect_kotakbas = Some(parse_rule_key(redirect_to.clone().unwrap())?);

            let fmt = redirect_to.unwrap();
            redirect_fmt = format!(" -> {}:{} {} {}", fmt.ip, fmt.port, fmt.eth, fmt.proto)
        };
        
        info!(
            "Add rule request: {}:{} {} -> {}{}",
            key.ip, key.port, key.proto, action, redirect_fmt
        );

        let mut bpf = self.bpf.lock().await;

        let rule_key = parse_rule_key(key)?;
        
        let rule_value = vanguard_common::maps::RuleValue {
            action: RuleAction::try_from(value.action).map_err(|_| Status::invalid_argument("invalid action"))?,
            to: redirect_kotakbas,
        };
        
        maps::RulesMap::add(&mut bpf, rule_key, rule_value).map_err(|_| Status::internal("ebpf map error"))?;
        
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

        let mut bpf = self.bpf.lock().await;

        let rule_key = parse_rule_key(key)?;
        
        maps::RulesMap::remove(&mut bpf, rule_key).map_err(|_| Status::internal("ebpf map error"))?;
        
        Ok(Response::new(()))
    }

    async fn get_stats(
        &self,
        _request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        info!("Get stats request");

        let mut bpf = self.bpf.lock().await;
        
        let stats = GlobalStats::get_total(&mut bpf)
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

fn parse_rule_key(key: vanguard_api::RuleKey) -> Result<vanguard_common::maps::RuleKey, Status> {
    Ok(vanguard_common::maps::RuleKey {
        ip: parse_ip(key.ip).map_err(|_| Status::invalid_argument("invalid ip"))?,
        port: key.port.try_into().map_err(|_| Status::invalid_argument("port should be uint16"))?,
        eth: parse_eth(key.eth).map_err(|_| Status::invalid_argument("invalid eth"))?,
        proto: parse_proto(key.proto).map_err(|_| Status::invalid_argument("invalid proto"))?,
    })
}

pub async fn start_grpc_server(bpf: Arc<Mutex<aya::Ebpf>>, addr: SocketAddr) -> ErrResult<()> {
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