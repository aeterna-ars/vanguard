use std::net::SocketAddr;

use tonic::transport::Channel;

use crate::{
    erret_result::ErrResult,
    maps::*,
    parsetrash::AsStrExt
};

use super::vanguard_api::{self, vanguard_client::*, *};

pub struct VanguardGrpcClient {
    pub inner: VanguardClient<Channel>,
}

impl VanguardGrpcClient {
    pub async fn connect(addr: SocketAddr) -> ErrResult<Self> {
        let endpoint = format!("http://{}", addr);
        let inner = VanguardClient::connect(endpoint).await?;
        Ok(Self { inner })
    }

    pub async fn connect_local() -> ErrResult<Self> {
        let endpoint = "127.0.0.1:8080";
        let inner = VanguardClient::connect(endpoint).await?;
        Ok(Self { inner })
    }

    pub async fn change_rate_limit(&mut self, limit: u32) -> Result<(), tonic::Status> {
        let request = tonic::Request::new(ChangeRateLimitRequest { limit });
        self.inner.change_rate_limit(request).await?;
        Ok(())
    }

    pub async fn change_block_time(&mut self, time: u64) -> Result<(), tonic::Status> {
        let request = tonic::Request::new(ChangeBlockTimeRequest { time });
        self.inner.change_block_time(request).await?;
        Ok(())
    }

    pub async fn block(&mut self, ip: String, block_until: u64) -> Result<(), tonic::Status> {
        let request = tonic::Request::new(BlockRequest { ip, block_until });
        self.inner.block(request).await?;
        Ok(())
    }

    pub async fn white(&mut self, ip: String) -> Result<(), tonic::Status> {
        let request = tonic::Request::new(WhiteRequest { ip });
        self.inner.white(request).await?;
        Ok(())
    }

    pub async fn add_rule(&mut self, rule: vanguard_common::maps2::Rule) -> Result<(), tonic::Status> {
        let k = rule.key;
        let v = rule.value;

        let key = RuleKey {
            ip: k.ip.as_str(),
            port: k.port as u32,
            eth: k.eth.as_str(),
            proto: k.proto.as_str(),
        };

        let mut redirect_to: Option<RuleKey> = None;

        if let Some(r) = v.to {
            redirect_to = Some(RuleKey {
                ip: r.ip.as_str(),
                port: r.port as u32,
                eth: r.eth.as_str(),
                proto: r.proto.as_str(),
            })
        }

        let value = RuleValue {
            action: v.action as u32,
            redirect_to,
        };

        let rule = Rule {
            key: Some(key),
            value: Some(value),
        };

        let request = tonic::Request::new(AddRuleRequest { rule: Some(rule) });
        self.inner.add_rule(request).await?;
        Ok(())
    }

    pub async fn del_rule(&mut self, rule_key: vanguard_common::maps2::RuleKey) -> Result<(), tonic::Status> {
        let rule = parse_rule_key(rule_key);

        let request = tonic::Request::new(DelRuleRequest { key: Some(rule) });
        self.inner.del_rule(request).await?;
        Ok(())
    }

    pub async fn get_stats(&mut self) -> Result<GlobalStats, tonic::Status> {
        let request = tonic::Request::new(GetStatsRequest {});
        let response = self.inner.get_stats(request).await?.into_inner();

        let stats = GlobalStats {
            total: response.total,
            dropped: response.dropped,
            passed: response.passed,
            tx: response.tx,
            redirected: response.redirected,
        };

        Ok(stats)
    }
}

fn parse_rule_key(key: vanguard_common::maps2::RuleKey) -> RuleKey {
    vanguard_api::RuleKey {
        ip: key.ip.as_str(),
        port: key.port as u32,
        eth: key.eth.as_str(),
        proto: key.proto.as_str(),
    }
}