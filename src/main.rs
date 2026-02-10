use anyhow::Result;
use chef::{commands::Commands, decode, encode, transform};
use clap::Parser;
use std::io::{self, Read};

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

fn trim_trailing_newlines(input: &[u8]) -> &[u8] {
    let mut end = input.len();
    while end > 0 && matches!(input[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    &input[..end]
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let trimmed_input = trim_trailing_newlines(&input);

    match &args.command {
        Commands::UrlEncode { all } => {
            println!(
                "{}",
                encode::url::encode(std::str::from_utf8(trimmed_input)?, *all)
            );
        }
        Commands::UrlDecode => {
            println!("{}", decode::url::decode(std::str::from_utf8(&input)?)?);
        }
        Commands::FromHex => {
            println!("{}", decode::hex::decode(std::str::from_utf8(&input)?)?);
        }
        Commands::FromUnix { millis } => {
            println!(
                "{}",
                transform::date::from_unix(std::str::from_utf8(trimmed_input)?, *millis)?
            );
        }
        Commands::ToUnix { millis } => {
            println!(
                "{}",
                transform::date::to_unix(std::str::from_utf8(trimmed_input)?, *millis)?
            );
        }
        Commands::Defang => {
            println!(
                "{}",
                encode::defang::encode(std::str::from_utf8(trimmed_input)?.trim())
            );
        }
    }

    Ok(())
}
