use anyhow::Result;
use chef::{
    commands::{
        Commands, CryptoCommands, DecodeCommands, EncodeCommands, NetworkCommands, TextCommands,
        TimeCommands,
    },
    decode, encode, transform,
};
use clap::{CommandFactory, Parser};
use clap_complete::generate;
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

    if let Commands::Completion { shell } = &args.command {
        let mut cmd = Args::command();
        let bin_name = cmd.get_name().to_string();
        generate(*shell, &mut cmd, bin_name, &mut io::stdout());
        return Ok(());
    }

    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let trimmed_input = trim_trailing_newlines(&input);
    let raw_input_str = std::str::from_utf8(&input)?;
    let trimmed_input_str = std::str::from_utf8(trimmed_input)?;

    match &args.command {
        Commands::Completion { .. } => unreachable!("completion is handled before stdin read"),
        Commands::Encode { command } => match command {
            EncodeCommands::Url { all } => {
                println!("{}", encode::url::encode(trimmed_input_str, *all));
            }
            EncodeCommands::Hex {
                delimiter,
                prefix,
                upper,
            } => {
                println!(
                    "{}",
                    encode::hex::encode(trimmed_input, delimiter, prefix, *upper)
                );
            }
            EncodeCommands::Base64 {
                url_safe,
                no_padding,
            } => {
                println!(
                    "{}",
                    encode::base64::encode(trimmed_input, *url_safe, *no_padding)
                );
            }
            EncodeCommands::Binary { delimiter, prefix } => {
                println!(
                    "{}",
                    encode::binary::encode(trimmed_input, delimiter, prefix)
                );
            }
            EncodeCommands::Base32 { no_padding, lower } => {
                println!(
                    "{}",
                    encode::base32::encode(trimmed_input, *no_padding, *lower)
                );
            }
            EncodeCommands::HtmlEntity => {
                println!("{}", encode::html_entity::encode(trimmed_input_str));
            }
            EncodeCommands::GzipBase64 { no_padding } => {
                println!(
                    "{}",
                    transform::gzip::compress_to_base64(trimmed_input, *no_padding)?
                );
            }
            EncodeCommands::Charset { to, output } => {
                let bytes = transform::charset::encode_from_utf8(trimmed_input_str, *to)?;
                println!(
                    "{}",
                    transform::charset::format_output_bytes(&bytes, *output)
                );
            }
        },
        Commands::Decode { command } => match command {
            DecodeCommands::Url => {
                println!("{}", decode::url::decode(raw_input_str)?);
            }
            DecodeCommands::Hex => {
                println!("{}", decode::hex::decode(raw_input_str)?);
            }
            DecodeCommands::Base64 { url_safe } => {
                println!("{}", decode::base64::decode(raw_input_str, *url_safe)?);
            }
            DecodeCommands::Binary => {
                println!("{}", decode::binary::decode(raw_input_str)?);
            }
            DecodeCommands::Base32 => {
                println!("{}", decode::base32::decode(raw_input_str)?);
            }
            DecodeCommands::HtmlEntity => {
                println!("{}", decode::html_entity::decode(raw_input_str));
            }
            DecodeCommands::GzipBase64 => {
                println!(
                    "{}",
                    transform::gzip::decompress_from_base64(raw_input_str)?
                );
            }
            DecodeCommands::Charset {
                from,
                input: format,
            } => {
                let bytes = transform::charset::parse_input_bytes(raw_input_str, *format)?;
                println!("{}", transform::charset::decode_to_utf8(&bytes, *from)?);
            }
        },
        Commands::Crypto { command } => match command {
            CryptoCommands::Hash { algorithm } => {
                println!("{}", transform::hash::hash(trimmed_input, *algorithm));
            }
            CryptoCommands::EncryptAesGcm {
                key_hex,
                nonce_hex,
                aad,
                no_padding,
            } => {
                println!(
                    "{}",
                    transform::aes_gcm::encrypt_to_base64(
                        trimmed_input,
                        key_hex,
                        nonce_hex,
                        aad,
                        *no_padding,
                    )?
                );
            }
            CryptoCommands::DecryptAesGcm {
                key_hex,
                nonce_hex,
                aad,
            } => {
                println!(
                    "{}",
                    transform::aes_gcm::decrypt_from_base64(
                        raw_input_str,
                        key_hex,
                        nonce_hex,
                        aad
                    )?
                );
            }
            CryptoCommands::XorSingle { key, output_hex } => {
                let out = transform::xor::xor_with_key(trimmed_input, &[*key])?;
                println!("{}", transform::xor::format_output(&out, *output_hex));
            }
            CryptoCommands::XorRepeat {
                key,
                hex_key,
                output_hex,
            } => {
                let key_bytes = transform::xor::parse_repeat_key(key, *hex_key)?;
                let out = transform::xor::xor_with_key(trimmed_input, &key_bytes)?;
                println!("{}", transform::xor::format_output(&out, *output_hex));
            }
            CryptoCommands::XorBruteforceSingleByte { top, min_score } => {
                for c in transform::xor::brute_force_single_byte(trimmed_input, *top, *min_score) {
                    println!(
                        "key=0x{:02x} score={:.3} text={}",
                        c.key, c.score, c.plaintext
                    );
                }
            }
        },
        Commands::Text { command } => match command {
            TextCommands::RegexReplace {
                pattern,
                replacement,
                global,
                multiline,
                dotall,
            } => {
                println!(
                    "{}",
                    transform::regex_replace::replace(
                        raw_input_str,
                        pattern,
                        replacement,
                        *global,
                        *multiline,
                        *dotall,
                    )?
                );
            }
            TextCommands::NormalizeUnicode { form } => {
                println!(
                    "{}",
                    transform::unicode::normalize(trimmed_input_str, *form)
                );
            }
            TextCommands::Defang => {
                println!("{}", encode::defang::encode(trimmed_input_str.trim()));
            }
        },
        Commands::Time { command } => match command {
            TimeCommands::FromUnix { millis } => {
                println!(
                    "{}",
                    transform::date::from_unix(trimmed_input_str, *millis)?
                );
            }
            TimeCommands::ToUnix { millis } => {
                println!("{}", transform::date::to_unix(trimmed_input_str, *millis)?);
            }
        },
        Commands::Network { command } => match command {
            NetworkCommands::CidrInfo => {
                println!("{}", transform::network::cidr_info(trimmed_input_str)?);
            }
            NetworkCommands::IpToInt => {
                println!("{}", transform::network::ip_to_int(trimmed_input_str)?);
            }
            NetworkCommands::IntToIp { v6 } => {
                println!("{}", transform::network::int_to_ip(trimmed_input_str, *v6)?);
            }
            NetworkCommands::DnsToDohPacket {
                name,
                qtype,
                id,
                endpoint,
            } => {
                let domain = match name {
                    Some(v) => v.as_str(),
                    None => trimmed_input_str,
                };
                let payload = transform::dns::build_doh_payload(domain, *qtype, *id)?;
                if let Some(ep) = endpoint {
                    println!("{}", transform::dns::build_doh_url(ep, &payload));
                } else {
                    println!("{payload}");
                }
            }
        },
    }

    Ok(())
}
