use anyhow::Result;
use chef::{commands::Commands, decode, encode};
use clap::Parser;
use std::io::{self, Read};

#[derive(Parser)]
#[command(version, about, long_about=None)]
#[command(propagate_version = true)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;

    match &args.command {
        Commands::UrlEncode { all } => {
            println!("{}", encode::url::encode(&String::from_utf8(input)?, *all));
        }
        Commands::UrlDecode => {
            println!("{}", decode::url::decode(&String::from_utf8(input)?)?);
        }
        Commands::FromHex => {
            println!("{}", decode::hex::decode(&String::from_utf8(input)?)?);
        }
    }

    Ok(())
}
