use clap::{Parser, Subcommand};
use vanguard_common::{config::*, error::VanguardError, *};
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
    pub fn exec_cmd() ->  ErrResult<()> {
        let cli = Cli::parse();

        if let Some(cmd) = cli.command {
            cmd.handle_cmd()?;
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
    pub fn handle_cmd(self) -> ErrResult<()> {
        match self {
            Self::Rules(cmd) => {
                RulesCommands::handle_rules(cmd)?;
            }
            Self::Stats => {
                Self::show_stats()?;
            }
        }

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
        rule: vanguard_common::maps::Rule,
    },

    Del {
        #[arg(short, long)]
        key: vanguard_common::maps::RuleKey,
    },
}

impl RulesCommands {
    pub fn handle_rules(self) -> ErrResult<()> {
        match self {
            Self::List => {
                Self::list()?;
            }
            Self::Add { rule } => {
                Self::add_rule(rule)?;
            }
            Self::Del { key } => {
                Self::del_rule(key)?;
            }
        }

        Ok(())
    }

    fn list() -> ErrResult<()> {


        Ok(())
    }

    fn add_rule(rule: vanguard_common::maps::Rule) -> ErrResult<()> {
        let grpc = VanguardGrpcClient::connect_local().await?;
        grpc.add_rule(rule)?;
        Ok(())
    }

    fn del_rule(key: vanguard_common::maps::RuleKey) -> ErrResult<()> {
        let grpc = VanguardGrpcClient::connect_local().await?;
        grpc.del_rule(key)?;
        Ok(())
    }
}