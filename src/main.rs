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
        Commands::EncodeCharset { to, output } => {
            let bytes =
                transform::charset::encode_from_utf8(std::str::from_utf8(trimmed_input)?, *to)?;
            println!(
                "{}",
                transform::charset::format_output_bytes(&bytes, *output)
            );
        }
        Commands::DecodeCharset {
            from,
            input: format,
        } => {
            let bytes =
                transform::charset::parse_input_bytes(std::str::from_utf8(&input)?, *format)?;
            println!("{}", transform::charset::decode_to_utf8(&bytes, *from)?);
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
