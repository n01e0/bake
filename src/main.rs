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
        Commands::ToHex {
            delimiter,
            prefix,
            upper,
        } => {
            println!(
                "{}",
                encode::hex::encode(trimmed_input, delimiter, prefix, *upper)
            );
        }
        Commands::ToBase64 {
            url_safe,
            no_padding,
        } => {
            println!(
                "{}",
                encode::base64::encode(trimmed_input, *url_safe, *no_padding)
            );
        }
        Commands::FromBase64 { url_safe } => {
            println!(
                "{}",
                decode::base64::decode(std::str::from_utf8(&input)?, *url_safe)?
            );
        }
        Commands::ToBinary { delimiter, prefix } => {
            println!(
                "{}",
                encode::binary::encode(trimmed_input, delimiter, prefix)
            );
        }
        Commands::FromBinary => {
            println!("{}", decode::binary::decode(std::str::from_utf8(&input)?)?);
        }
        Commands::ToBase32 { no_padding, lower } => {
            println!(
                "{}",
                encode::base32::encode(trimmed_input, *no_padding, *lower)
            );
        }
        Commands::FromBase32 => {
            println!("{}", decode::base32::decode(std::str::from_utf8(&input)?)?);
        }
        Commands::ToHtmlEntity => {
            println!(
                "{}",
                encode::html_entity::encode(std::str::from_utf8(trimmed_input)?)
            );
        }
        Commands::FromHtmlEntity => {
            println!(
                "{}",
                decode::html_entity::decode(std::str::from_utf8(&input)?)
            );
        }
        Commands::RegexReplace {
            pattern,
            replacement,
            global,
            multiline,
            dotall,
        } => {
            println!(
                "{}",
                transform::regex_replace::replace(
                    std::str::from_utf8(&input)?,
                    pattern,
                    replacement,
                    *global,
                    *multiline,
                    *dotall,
                )?
            );
        }
        Commands::Hash { algorithm } => {
            println!("{}", transform::hash::hash(trimmed_input, *algorithm));
        }
        Commands::ToGzipBase64 { no_padding } => {
            println!(
                "{}",
                transform::gzip::compress_to_base64(trimmed_input, *no_padding)?
            );
        }
        Commands::FromGzipBase64 => {
            println!(
                "{}",
                transform::gzip::decompress_from_base64(std::str::from_utf8(&input)?)?
            );
        }
        Commands::EncryptAesGcm {
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
        Commands::DecryptAesGcm {
            key_hex,
            nonce_hex,
            aad,
        } => {
            println!(
                "{}",
                transform::aes_gcm::decrypt_from_base64(
                    std::str::from_utf8(&input)?,
                    key_hex,
                    nonce_hex,
                    aad,
                )?
            );
        }
        Commands::XorSingle { key, output_hex } => {
            let out = transform::xor::xor_with_key(trimmed_input, &[*key])?;
            println!("{}", transform::xor::format_output(&out, *output_hex));
        }
        Commands::XorRepeat {
            key,
            hex_key,
            output_hex,
        } => {
            let key_bytes = transform::xor::parse_repeat_key(key, *hex_key)?;
            let out = transform::xor::xor_with_key(trimmed_input, &key_bytes)?;
            println!("{}", transform::xor::format_output(&out, *output_hex));
        }
        Commands::XorBruteforceSingleByte { top, min_score } => {
            for c in transform::xor::brute_force_single_byte(trimmed_input, *top, *min_score) {
                println!(
                    "key=0x{:02x} score={:.3} text={}",
                    c.key, c.score, c.plaintext
                );
            }
        }
        Commands::NormalizeUnicode { form } => {
            println!(
                "{}",
                transform::unicode::normalize(std::str::from_utf8(trimmed_input)?, *form)
            );
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
        Commands::CidrInfo => {
            println!(
                "{}",
                transform::network::cidr_info(std::str::from_utf8(trimmed_input)?)?
            );
        }
        Commands::IpToInt => {
            println!(
                "{}",
                transform::network::ip_to_int(std::str::from_utf8(trimmed_input)?)?
            );
        }
        Commands::IntToIp { v6 } => {
            println!(
                "{}",
                transform::network::int_to_ip(std::str::from_utf8(trimmed_input)?, *v6)?
            );
        }
        Commands::DnsToDohPacket {
            name,
            qtype,
            id,
            endpoint,
        } => {
            let domain = match name {
                Some(v) => v.as_str(),
                None => std::str::from_utf8(trimmed_input)?,
            };
            let payload = transform::dns::build_doh_payload(domain, *qtype, *id)?;
            if let Some(ep) = endpoint {
                println!("{}", transform::dns::build_doh_url(ep, &payload));
            } else {
                println!("{payload}");
            }
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
