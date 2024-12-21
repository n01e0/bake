use clap::Parser;
use anyhow::Result;
use chef::encode::url;
use chef::commands::Commands;
use std::io::{self, Read};



#[derive(Parser)]
#[command(version, about, long_about=None)]
#[command(propagate_version = true)]
struct Args {
    #[command(subcommand)]
    command: Commands
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;

    match &args.command {
        Commands::UrlEncode { strict, all } => {
            println!("{}", url::encode(&input, *strict, *all));
        }
    }

    Ok(())
}
