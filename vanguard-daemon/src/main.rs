use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::signal::unix::*;

use aya::{
    Ebpf, EbpfLoader, VerifierLogLevel, include_bytes_aligned, programs::{Xdp, XdpMode, xdp::XdpLinkId},
};
use aya_log::EbpfLogger;

use libsystemd::daemon::{self, *};

use vanguard_common::{
    brevno::{self, *}, config::{
        GrpcApi,
        VanguardConfig
    }, erret_result::*, error::VanguardError, maps,
};

use vanguard_grpc::server::start_grpc_server;

struct XdpDaemon {
    pub bpf: Arc<Mutex<Ebpf>>,
    pub link_id: XdpLinkId,
}

impl XdpDaemon {
    async fn load() -> ErrResult<Self> {
        info!("Starting daemon...");

        let iface = "wlp2s0";

        Self::notify();

        let mut bpf = EbpfLoader::new()
            .verifier_log_level(VerifierLogLevel::all()) 
            .load(aya::include_bytes_aligned!("../../target/bpfel-unknown-none/release/vanguard-xdp"))?;

        // let mut bpf = aya::Ebpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/vanguard-xdp"))?;

        let program: &mut Xdp = bpf.program_mut("main").unwrap().try_into()?;
        program.load()?;

        let link_id = program.attach(iface, XdpMode::default())
            .map_err(|_| VanguardError::Ebpf("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb"))?;

        let mut daemon = XdpDaemon {
            bpf: Arc::new(Mutex::new(bpf)),
            link_id,
        };

        daemon.init_logger().await?;

        Ok(daemon)
    }

    async fn init_logger(&mut self) -> ErrResult<()> {
        let mut bpf = self.bpf.lock().await;

        env_logger::init();

        match EbpfLogger::init(&mut bpf) {
            Err(e) => {
                info!("Failed to init logger: {}", e);
            }
            Ok(logger) => {
                let mut logger = tokio::io::unix::AsyncFd::with_interest (
                    logger,
                    tokio::io::Interest::READABLE,
                )?;
                tokio::task::spawn(async move {
                    loop {
                        let mut guard = logger.readable_mut().await.unwrap();
                        guard.get_inner_mut().flush();
                        guard.clear_ready();
                    }
                });
            }
        }

        Ok(())
    }

    async fn apply_cfg(&mut self, config: VanguardConfig) -> ErrResult<()> {
        let mut bpf = self.bpf.lock().await;

        maps::ConfigMap::write(&mut bpf, config.config)?;

        for ip in config.blacklist {
            maps::BlocklistMap::block(&mut bpf, ip.ip.0, ip.blocked_until)?;
        }

        for ip in config.whitelist {
            maps::WhitelistMap::insert(&mut bpf, ip.0)?;
        }

        for rule in config.rules {
            maps::RulesMap::add(&mut bpf, rule.key, rule.value)?;
        }

        if config.grpc.up {
            self.grpc(&config.grpc).await?;
        }

        Ok(())
    }

    fn notify() {
        if daemon::booted() {
            if let Err(e) = daemon::notify(false, &[NotifyState::Ready]) {
                error!("Failed to notify systemd: {}", e);
            } else {
                info!("Systemd notified: READY=1");
            }
        } else {
            info!("Not running under systemd");
        }
    }

    async fn grpc(&self, grpc: &GrpcApi) -> ErrResult<()> {
        let default_addr = "[::1]:8080".parse().expect("valid addr");

        let bpf = self.bpf.clone();

        tokio::spawn(async move {
            if let Err(e) = start_grpc_server(bpf, default_addr).await {
                error!("local grpc server failed: {}", e);
            }
        });

        let bpf = self.bpf.clone();
        if grpc.up {
            let addr = grpc.addr;
            tokio::spawn(async move {
                if let Err(e) = start_grpc_server(bpf, addr).await {
                    error!("grpc server failed: {}", e);
                }
            });
        }

        Ok(())
    }

    async fn run(mut self) -> ErrResult<()> {
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sighup = signal(SignalKind::hangup())?;

        loop {
            tokio::select! {
                _ = sigterm.recv() => {
                    self.cleanup().await?;
                    info!("Shutting down...");
                    break Ok(());
                }
                _ = sighup.recv() => {
                    info!("Reloading config...");
                    match VanguardConfig::load("config.yaml") {
                        Ok(new_config) => {
                            if let Err(e) = self.apply_cfg(new_config).await {
                                error!("Failed to apply reloaded config: {}", e);
                            } else {
                                info!("Config reloaded");
                            }
                        }
                        Err(e) => error!("Failed to reload config: {}", e),
                    }
                }
            }
        }
    }

    async fn cleanup(self) -> ErrResult<()> {
        let mut bpf = self.bpf.lock().await;

        let program: &mut Xdp = bpf.program_mut("core").unwrap().try_into()?;

        program.detach(self.link_id)
            .map_err(|_| VanguardError::Ebpf("failed to detach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb"))?;

        program.unload()?;

        Ok(())
    }
}

brevno::init_global_logger!(128, 128, brevno::log::LogLevel::Info);

#[tokio::main]
async fn main() -> ErrResult<()> {
    std::thread::spawn( || {
        brevno::log::Logger::<128, 128>::init(log::LogLevel::Info);
    }
    );

    let daemon = XdpDaemon::load().await?;
    daemon.run().await?;

    Ok(())
}