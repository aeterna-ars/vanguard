use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::signal::unix::*;

use aya::{
    Ebpf,
    EbpfLoader,
    VerifierLogLevel,
    programs::{
        Xdp,
        XdpMode,
        xdp::XdpLinkId
    },
};
use aya_log::EbpfLogger;

use libsystemd::daemon::{self, *};

use vanguard_core::xdp::{
    brevno::*,
    erret_result::*,
    error::VanguardError,
    maps,
};
use vanguard_grpc::server::*;
use vanguard_config::config::*;

struct XdpDaemon {
    pub bpf: Arc<Mutex<Ebpf>>,
    pub link_id: XdpLinkId,
}

impl XdpDaemon {
    async fn load(config_path: &str) -> ErrResult<Self> {
        info!("Starting daemon...");

        let iface = "wlp2s0";
        let cfg = VanguardConfig::load(config_path)?;

        Self::notify();

        let mut bpf = EbpfLoader::new()
            .verifier_log_level(VerifierLogLevel::all()) 
            .default_map_pin_directory("/sys/fs/bpf/vanguard")
            .load(aya::include_bytes_aligned!("../../target/bpfel-unknown-none/release/vanguard-xdp"))?;

        let program: &mut Xdp = bpf.program_mut("main").unwrap().try_into()?;
        program.load()?;

        let link_id = program.attach(iface, XdpMode::default())
            .map_err(|_| VanguardError::Ebpf("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb"))?;

        let mut daemon = XdpDaemon {
            bpf: Arc::new(Mutex::new(bpf)),
            link_id,
        };

        daemon.init_logger().await?;

        daemon.apply_cfg(cfg).await?;

        Ok(daemon)
    }

    async fn mount() -> ErrResult<()> {
        std::fs::create_dir_all("/sys/fs/bpf/vanguard")?;

        Ok(())
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

        maps::config::ConfigMap::write(&mut bpf, config.config)?;

        for block in config.blacklist {
            maps::blacklist::BlocklistMap::block(&mut bpf, block.ip, block.blocked_until)?;
        }

        for ip in config.whitelist {
            maps::whitelist::WhitelistMap::insert(&mut bpf, ip)?;
        }

        for rule in config.rules {
            maps::rules::RulesMap::add(&mut bpf, rule.key, rule.value)?;
        }

        self.grpc(&config.grpc).await?;

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
        let default_addr: std::net::SocketAddr = "127.0.0.1:8080".parse().expect("invalid addr");

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

init_global_logger!(128, 128, log::LogLevel::Info);

#[tokio::main]
async fn main() -> ErrResult<()> {
    let config_path = "/home/user/projects/projects/vanguard/vanguard.yml";

    // std::thread::spawn( || {
    //     let logger = log::Logger::<128, 128>::init(log::LogLevel::Info);
    //     loop {
    //         println!("{}", logger.read_log().unwrap().decode().unwrap())
    //     }
    // });

    let daemon = XdpDaemon::load(config_path).await?;
    daemon.run().await?;

    Ok(())
}