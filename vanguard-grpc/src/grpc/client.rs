use std::net::SocketAddr;

use tonic::transport::Channel;

use super::vanguard_api::{
    vanguard_client::*,
    *,
};

use vanguard_core::{
    xdp::maps::{
        rules::*,
        stats::*,
    },
    common::commons::Parse,
};

use erret_result::*;

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

    pub async fn change_rate_limit(&mut self, limit: u32) -> ErrResult<()> {
        let request = tonic::Request::new(ChangeRateLimitRequest { limit });
        self.inner.change_rate_limit(request).await?;
        Ok(())
    }

    pub async fn change_block_time(&mut self, time: u64) -> ErrResult<()> {
        let request = tonic::Request::new(ChangeBlockTimeRequest { time });
        self.inner.change_block_time(request).await?;
        Ok(())
    }

    pub async fn block(&mut self, ip: String, block_until: u64) -> ErrResult<()> {
        let request = tonic::Request::new(BlockRequest { ip, block_until });
        self.inner.block(request).await?;
        Ok(())
    }

    pub async fn white(&mut self, ip: String) -> ErrResult<()> {
        let request = tonic::Request::new(WhiteRequest { ip });
        self.inner.white(request).await?;
        Ok(())
    }

    pub async fn add_rule(&mut self, key: XdpRuleKey, value: XdpRuleValue) -> ErrResult<()> {
        let k = RuleKey {
            ip: key.ip.as_str()?,
            port: key.port.0 as u32,
            eth: key.eth.as_str()?,
            proto: key.proto.as_str()?,
        };

        let v = RuleValue {
            action: value.action.as_str()?,
            redirect: Some(parse_rule_key(value.redirect)?),
        };

        let request = tonic::Request::new(AddRuleRequest {
            key: Some(k),
            value: Some(v)
        });

        self.inner.add_rule(request).await?;
        Ok(())
    }

    pub async fn del_rule(&mut self, rule_key: XdpRuleKey) -> ErrResult<()> {
        let rule = parse_rule_key(rule_key);
        let request = tonic::Request::new(DelRuleRequest { key: Some(rule?) });
        self.inner.del_rule(request).await?;
        Ok(())
    }

    pub async fn get_stats(&mut self) -> ErrResult<XdpGlobalStats> {
        let request = tonic::Request::new(GetStatsRequest {});
        let response = self.inner.get_stats(request).await?.into_inner();

        let stats = XdpGlobalStats {
            total: response.total,
            dropped: response.dropped,
            passed: response.passed,
            tx: response.tx,
            redirected: response.redirected,
        };

        Ok(stats)
    }
}

fn parse_rule_key(key: XdpRuleKey) -> ErrResult<RuleKey> {
    Ok(super::vanguard_api::RuleKey {
        ip: key.ip.as_str()?,
        port: key.port.0 as u32,
        eth: key.eth.as_str()?,
        proto: key.proto.as_str()?,
    })
}