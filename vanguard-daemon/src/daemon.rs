use aya::{
    Ebpf,
    programs::{Xdp, XdpMode, xdp::XdpLinkId},
};
use aya_log::EbpfLogger;

use libsystemd::daemon::{self, *};

use tokio::signal::unix::*;

use vanguard_common::{config::{GrpcApi, VanguardConfig}, error::VanguardError, maps, *};
use vanguard_grpc::server::start_grpc_server;

struct XdpDaemon {
    pub bpf: Ebpf,
    pub link_id: XdpLinkId,
}

impl XdpDaemon {
    fn load(config: VanguardConfig) -> ErrResult<Self> {
        println!("Starting daemon...");

        Self::notify()?;

        let mut bpf = aya::Ebpf::load_file("../target/bpfel-unknown-none/release/vanguard-core")?;

        let program: &mut Xdp = bpf.program_mut("core").unwrap().try_into()?;
        program.load()?;

        let link_id = program.attach(&config.iface, XdpMode::default())
            .map_err(|_| VanguardError::Ebpf("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb"))?;

        let xdp = XdpDaemon {
            bpf,
            link_id,
        };

        Ok(xdp)
    }

    fn init_logger(mut self) -> ErrResult<()> {
        env_logger::init();

        match EbpfLogger::init(&mut self.bpf) {
            Err(e) => {
                println!("Failed to init logger: {}", e);
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

    fn cleanup(mut self) -> ErrResult<()> {
        let program: &mut Xdp = self.bpf.program_mut("core").unwrap().try_into()?;

        program.detach(self.link_id)
            .map_err(|_| VanguardError::Ebpf("failed to detach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb"))?;

        program.unload()?;

        Ok(())
    }

    fn apply_cfg(mut self, config: VanguardConfig) -> ErrResult<()> {
        maps::ConfigMap::write(&mut self.bpf, config.config)?;

        for ip in config.blacklist {
            maps::BlocklistMap::block(&mut self.bpf, ip.ip.0, ip.blocked_until)?;
        }

        for ip in config.whitelist {
            maps::WhitelistMap::insert(&mut self.bpf, ip.0)?;
        }

        for rule in config.rules {
            maps::RulesMap::add(&mut self.bpf, rule.key, rule.value)?;
        }

        if config.grpc.up {
            Self::grpc(&mut self.bpf, config.grpc)?;
        }

        Ok(())
    }

    fn notify() -> ErrResult<()> {
        if daemon::booted() {
            if let Err(e) = daemon::notify(false, &[NotifyState::Ready]) {
                eprintln!("Failed to notify systemd: {}", e);
            } else {
                println!("Systemd notified: READY=1");
            }
        } else {
            println!("Not running under systemd");
        }

        Ok(())
    }

    async fn pidoras(self) -> ErrResult<()> {
        let pid = std::process::id();
        std::fs::write("/tmp/vanguard.pid", pid.to_string())?;
        println!("PID file created: {}", pid);

        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sighup = signal(SignalKind::hangup())?;

        loop {
            tokio::select! {
                _ = sigterm.recv() => {
                    println!("Shutting down...");
                    break;
                }
                _ = sighup.recv() => {
                    println!("Reloading config...");
                    if let Ok(new_config) = VanguardConfig::load("config.yaml") {
                        self.apply_cfg(new_config)?;
                        println!("Config reloaded");
                    } else {
                        eprintln!("Failed to reload config");
                    }
                }
            }
        }

        std::fs::remove_file("/tmp/vanguard.pid").ok();
        println!("Daemon stopped");

        Ok(())
    }

    fn grpc(bpf: &mut Ebpf, grpc: GrpcApi) -> ErrResult<()> {
        let default_addr = "[::1]:8080".parse()?;
        tokio::spawn(async move {
            start_grpc_server(*bpf, default_addr).await?;
        });

        if grpc.up {
            tokio::spawn(async move {
                start_grpc_server(*bpf, grpc.addr).await?;
            });
        }

        Ok(())
    }
}