use clap::{Parser, Subcommand};
use vanguard_common::{config::*, error::VanguardError, maps::{Rule, *}, *};
use vanguard_grpc::{client::VanguardGrpcClient, vanguard_api::Rule};

#[derive(Parser)]
#[command(name = "vanguard")]
#[command(about = "XDP-based firewall", long_about)]
#[command(version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

impl Cli {
    pub fn exec_cmd() ->  ErrResult<()> {
        let cli = Cli::parse();

        if let Some(cmd) = cli.command {
            cmd.match_cmd()?;
        };

        Ok(())
    }
}

#[derive(Subcommand)]
pub enum Commands {
    Start {
        #[arg(short, long, default_value = "config.yaml")]
        config: String,

        #[arg(short, long, default_value = "eth0")]
        iface: String,

        #[arg(short, long, default_value = "true")]
        foreground: bool,
    },

    Stop,

    Reload,

    Status,

    #[command(subcommand)]
    Rules(RulesCommands),

    Stats,
}

impl Commands {
    pub fn match_cmd(self) -> ErrResult<()> {
        match self {
            Self::Start { config, iface, foreground } => {
                Self::start_daemon(config, iface, foreground)?;
            }
            Self::Stop => {
                Self::stop_daemon()?;
            }
            Self::Reload => {
                Self::reload_config()?;
            }
            Self::Status => {
                Self::show_status()?;
            }
            Self::Rules(cmd) => {
                Self::handle_rules(cmd)?;
            }
            Self::Stats => {
                Self::show_stats()?;
            }
        }

        Ok(())
    }

    fn start_daemon(config: String, iface: String, foreground: bool) -> ErrResult<()> {
        

        Ok(())
    }

    fn stop_daemon() -> ErrResult<()> {
        println!("Stopping daemon...");

        let pid = match std::fs::read_to_string("/tmp/vanguard.pid") {
            Ok(content) => content.trim().parse::<u32>()?,
            Err(_) => {
                eprintln!("PID file not found. Trying to find process...");
                // ps | grep vanguard
                return Err(VanguardError::Daemon("PID file not found".to_string()));
            }
        };

        unsafe {
            let ret = libc::kill(pid as i32, libc::SIGTERM);
            if ret < 0 {
                return Err(VanguardError::Daemon(format!("kill daemon error: {}", std::io::Error::last_os_error())?));
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(500));

        if std::path::Path::new("/tmp/vanguard.pid").exists() {
            eprintln!("Process didn't exit cleanly, checking...");
            let status = unsafe {
                libc::kill(pid as i32, 0)
            };
            if status == 0 {
                eprintln!("Process still alive, sending SIGKILL...");
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
            }
            std::fs::remove_file("/tmp/vanguard.pid").ok();
        }
        
        println!("Daemon stopped");
        Ok(())
    }

    fn reload_config() -> ErrResult<()> {
        println!("Reloading configuration...");
    
        let pid = std::fs::read_to_string("/tmp/vanguard.pid")?
            .trim()
            .parse::<u32>()?;

        unsafe {
            let ret = libc::kill(pid as i32, libc::SIGHUP);
            if ret < 0 {
                return Err(VanguardError::Daemon(format!("failed to send SIGHUP: {}", std::io::Error::last_os_error())?));
            }
        }
        
        println!("SIGHUP sent to PID {}", pid);
        Ok(())
    }

    fn show_status() -> ErrResult<()> {
        println!("Daemon status:");
    
        if let Ok(content) = std::fs::read_to_string("/tmp/vanguard.pid") {
            let pid = content.trim().parse::<u32>()?;
            println!("PID: {}", pid);
            
            let alive = unsafe { libc::kill(pid as i32, 0) == 0 };
            println!("Status: {}", if alive { "Running" } else { "Dead" });
        } else {
            println!("Status: Not running");
            return Ok(());
        }
        
        let xdp_status = std::fs::exists("/sys/fs/bpf/vanguard")?;
        println!("XDP program: {}", if xdp_status { "Loaded" } else { "Not loaded" });
        
        Ok(())
    }

    fn handle_rules(cmd: RulesCommands) -> ErrResult<()> {


        Ok(())
    }

    fn show_stats() -> ErrResult<()> {


        Ok(())
    }
}

#[derive(Subcommand)]
pub enum RulesCommands {
    List,
    
    Add {
        #[arg(short, long)]
        rule: Rule,
    },
    
    Del {
        #[arg(short, long)]
        key: RuleKey,
    },
}

impl RulesCommands {
    pub fn match_rules(self) -> ErrResult<()> {
        match self {
            Self::List => {
                Self::list()?;
            }
            Self::Add { key, value } => {
                Self::add_rule(key, value)?;
            }
            Self::Remove { key, value } => {
                Self::remove_rule(key, value)?;
            }
        }

        Ok(())
    }

    fn list() -> ErrResult<()> {


        Ok(())
    }

    fn add_rule(key: RuleKey, value: RuleValue) -> ErrResult<()> {
        let cli = VanguardGrpcClient::connect_local().await?;

        let rule = Rule {
            ip: key.ip.0,
            port: ,
            eth,
            proto,
            action,
            to,
            to_ip,
            to_port,
            to_eth,
            to_proto,
        };

        cli.add_rule(rule)?;

        Ok(())
    }

    fn del_rule(key: RuleKey, value: RuleValue) -> ErrResult<()> {
        let cli = VanguardGrpcClient::connect_local().await?;

        let rule = Rule {
            ip,
            port,
            eth,
            proto,
            action,
            to,
            to_ip,
            to_port,
            to_eth,
            to_proto,
        };

        cli.del_rule(rule)?;

        Ok(())
    }

    fn flush() -> ErrResult<()> {


        Ok(())
    }
}