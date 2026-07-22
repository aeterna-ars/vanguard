use clap::{Parser, Subcommand};
use vanguard_common::{erret_result::*};
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
    #[command(subcommand)]
    Rules(RulesCommands),

    Stats,
}

impl Commands {
    pub async fn handle_cmd(self) -> ErrResult<()> {
        match self {
            Self::Rules(cmd) => {
                RulesCommands::handle_rules(cmd).await?;
            }
            Self::Stats => {
                Self::show_stats().await?;
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
pub enum RulesCommands {
    List,

    Add {
        #[command(subcommand)]
        rule: vanguard_common::maps::Rule,
    },

    Del {
        #[command(subcommand)]
        key: vanguard_common::maps::RuleKey,
    },
}

impl RulesCommands {
    pub async fn handle_rules(self) -> ErrResult<()> {
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

    async fn add_rule(rule: vanguard_common::maps::Rule) -> ErrResult<()> {
        let mut grpc = VanguardGrpcClient::connect_local().await?;
        grpc.add_rule(rule).await?;
        Ok(())
    }

    async fn del_rule(key: vanguard_common::maps::RuleKey) -> ErrResult<()> {
        let mut grpc = VanguardGrpcClient::connect_local().await?;
        grpc.del_rule(key).await?;
        Ok(())
    }
}