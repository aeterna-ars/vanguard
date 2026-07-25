use clap::{Parser, Subcommand};
use vanguard_common::{erret_result::*, maps::*, parse::AsStrExt};
use vanguard_grpc::{client::VanguardGrpcClient};

#[derive(Parser)]
#[command(name = "vanguard")]
#[command(about = "XDP-based firewall", long_about)]
#[command(version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}
impl Cli {
    pub async fn exec_cmd() ->  ErrResult<()> {
        let cli = Cli::parse();

        if let Some(cmd) = cli.command {
            cmd.handle_cmd().await?;
        };

        Ok(())
    }
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "XDP rules commands", long_about)]
    #[command(subcommand)]
    Rules(RulesCommands),

    #[command(about = "Black or whitelist IP", long_about)]
    #[command(subcommand)]
    Lists(ListsCommands),

    #[command(about = "XDP global stats", long_about)]
    Stats,
}
impl Commands {
    pub async fn handle_cmd(self) -> ErrResult<()> {
        match self {
            Self::Rules(cmd) => {
                RulesCommands::handle(cmd).await?;
            }
            Self::Stats => {
                Self::show_stats().await?;
            }
            Self::Lists(cmd) => {
                ListsCommands::handle(cmd).await?;
            }
        }

        Ok(())
    }

    async fn show_stats() -> ErrResult<()> {
        let mut grpc = VanguardGrpcClient::connect_local().await?;
        let stats = grpc.get_stats().await?;

        println!();
        println!("VANGUARD PACKET STATS:");
        println!("  total: {}", stats.total);
        println!("  dropped: {}", stats.dropped);
        println!("  passed: {}", stats.passed);
        println!("  tx: {}", stats.tx);
        println!("  redirected: {}", stats.redirected);
        println!();

        Ok(())
    }
}

#[derive(Subcommand)]
pub enum ListsCommands {
    #[command(subcommand)]
    Blacklist(BlacklistCommands),

    #[command(subcommand)]
    Whitelist(WhitelistCommands),
}
impl ListsCommands {
    pub async fn handle(self) -> ErrResult<()> {
        match self {
            Self::Blacklist( cmd ) => {
                BlacklistCommands::handle(cmd).await?;
            }
            Self::Whitelist( cmd ) => {
                WhitelistCommands::handle(cmd).await?;
            }
        }

        Ok(())
    }
}

#[derive(Subcommand)]
pub enum BlacklistCommands {
    #[command(about = "Add to XDP blacklist", long_about)]
    Block {
        #[arg(long, value_parser = vanguard_common::parse::cli::parse_ip_arg)]
        ip: String,

        #[arg(long)]
        until: u64,
    },

    #[command(about = "Delete from XDP blacklist", long_about)]
    Del {
        #[arg(long, value_parser = vanguard_common::parse::cli::parse_ip_arg)]
        ip: String,
    },
}
impl BlacklistCommands {
    pub async fn handle(self) -> ErrResult<()> {
        match self {
            Self::Block { ip, until } => {
                Self::block(ip, until).await?;
            }
            Self::Del { ip } => {
                Self::delete(ip).await?;
            }
        }

        Ok(())
    }

    async fn block(ip: Ip, blocked_until: u64) -> ErrResult<()> {
        let mut grpc = VanguardGrpcClient::connect_local().await?;
        grpc.block(ip.as_str(), blocked_until).await?;
        Ok(())
    }

    async fn delete(ip: Ip) -> ErrResult<()> {
        let mut grpc = VanguardGrpcClient::connect_local().await?;
        grpc.block(ip.as_str(), 0).await?;
        Ok(())
    }
}

#[derive(Subcommand)]
pub enum WhitelistCommands {
    #[command(about = "Add to XDP whitelist", long_about)]
    White {
        #[arg(long, value_parser = vanguard_common::parse::cli::parse_ip_arg)]
        ip: String,
    },

    #[command(about = "Delete from XDP whitelist", long_about)]
    Del {
        #[arg(long, value_parser = vanguard_common::parse::cli::parse_ip_arg)]
        ip: String,
    },
}
impl WhitelistCommands {
    pub async fn handle(self) -> ErrResult<()> {
        match self {
            Self::White { ip } => {
                Self::white(ip).await?;
            }
            Self::Del { ip } => {
                Self::delete(ip).await?;
            }
        }

        Ok(())
    }

    async fn white(ip: Ip) -> ErrResult<()> {
        let mut grpc = VanguardGrpcClient::connect_local().await?;
        grpc.white(ip.as_str()).await?;
        Ok(())
    }

    async fn delete(ip: Ip) -> ErrResult<()> {
        let mut grpc = VanguardGrpcClient::connect_local().await?;
        grpc.block(ip.as_str(), 0).await?;
        Ok(())
    }
}

#[derive(Subcommand)]
pub enum RulesCommands {
    #[command(about = "Rules list", long_about)]
    List,

    #[command(about = "XDP add rule", long_about)]
    Add {
        #[command(flatten)]
        rule: ,

        
    },

    #[command(about = "XDP delete rule", long_about)]
    Del {
        #[command(flatten)]
        key: ,
    },
}
impl RulesCommands {
    pub async fn handle(self) -> ErrResult<()> {
        match self {
            Self::List => {
                Self::list().await?;
            }
            Self::Add { rule } => {
                Self::add_rule(rule).await?;
            }
            Self::Del { key } => {
                Self::del_rule(key).await?;
            }
        }

        Ok(())
    }

    async fn list() -> ErrResult<()> {


        Ok(())
    }

    async fn add_rule(rule: vanguard_common::maps2::Rule) -> ErrResult<()> {
        let mut grpc = VanguardGrpcClient::connect_local().await?;
        grpc.add_rule(rule).await?;
        Ok(())
    }

    async fn del_rule(key: vanguard_common::maps2::RuleKey) -> ErrResult<()> {
        let mut grpc = VanguardGrpcClient::connect_local().await?;
        grpc.del_rule(key).await?;
        Ok(())
    }
}