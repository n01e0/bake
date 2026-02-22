use anyhow::{anyhow, Result};
use bake::{
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

#[derive(Default)]
struct StdinCache {
    bytes: Option<Vec<u8>>,
}

impl StdinCache {
    fn bytes(&mut self) -> Result<&[u8]> {
        if self.bytes.is_none() {
            let mut input = Vec::new();
            io::stdin().read_to_end(&mut input)?;
            self.bytes = Some(input);
        }
        Ok(self.bytes.as_deref().unwrap_or_default())
    }

    fn trimmed_bytes(&mut self) -> Result<&[u8]> {
        Ok(trim_trailing_newlines(self.bytes()?))
    }

    fn raw_str<'a>(&'a mut self, what: &str) -> Result<&'a str> {
        let bytes = self.bytes()?;
        std::str::from_utf8(bytes).map_err(|e| anyhow!("{what} must be UTF-8: {e}"))
    }

    fn trimmed_str<'a>(&'a mut self, what: &str) -> Result<&'a str> {
        let bytes = self.trimmed_bytes()?;
        std::str::from_utf8(bytes).map_err(|e| anyhow!("{what} must be UTF-8: {e}"))
    }

    fn require_trimmed<'a>(&'a mut self, what: &str) -> Result<&'a str> {
        let s = self.trimmed_str(what)?;
        if s.is_empty() {
            Err(anyhow!(
                "{what} is required (pass via stdin or command option)"
            ))
        } else {
            Ok(s)
        }
    }
}

fn option_or_stdin(
    option_value: &Option<String>,
    stdin: &mut StdinCache,
    what: &str,
) -> Result<String> {
    match option_value {
        Some(v) => Ok(v.clone()),
        None => Ok(stdin.require_trimmed(what)?.to_string()),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Commands::Completion { shell } = &args.command {
        let mut cmd = Args::command();
        let bin_name = cmd.get_name().to_string();
        generate(*shell, &mut cmd, bin_name, &mut io::stdout());
        return Ok(());
    }

    let mut stdin = StdinCache::default();

    match &args.command {
        Commands::Completion { .. } => unreachable!("completion is handled before stdin read"),
        Commands::Encode { command } => match command {
            EncodeCommands::Url { all } => {
                println!("{}", encode::url::encode(stdin.trimmed_str("input")?, *all));
            }
            EncodeCommands::Hex {
                delimiter,
                prefix,
                upper,
            } => {
                println!(
                    "{}",
                    encode::hex::encode(stdin.trimmed_bytes()?, delimiter, prefix, *upper)
                );
            }
            EncodeCommands::Base64 {
                url_safe,
                no_padding,
            } => {
                println!(
                    "{}",
                    encode::base64::encode(stdin.trimmed_bytes()?, *url_safe, *no_padding)
                );
            }
            EncodeCommands::Base58 => {
                println!("{}", encode::base58::encode(stdin.trimmed_bytes()?));
            }
            EncodeCommands::Base85 => {
                println!("{}", encode::base85::encode(stdin.trimmed_bytes()?));
            }
            EncodeCommands::Base91 => {
                println!("{}", encode::base91::encode(stdin.trimmed_bytes()?));
            }
            EncodeCommands::Binary { delimiter, prefix } => {
                println!(
                    "{}",
                    encode::binary::encode(stdin.trimmed_bytes()?, delimiter, prefix)
                );
            }
            EncodeCommands::Base32 { no_padding, lower } => {
                println!(
                    "{}",
                    encode::base32::encode(stdin.trimmed_bytes()?, *no_padding, *lower)
                );
            }
            EncodeCommands::QuotedPrintable { binary } => {
                println!(
                    "{}",
                    encode::quoted_printable::encode(stdin.trimmed_bytes()?, *binary)
                );
            }
            EncodeCommands::HtmlEntity => {
                println!(
                    "{}",
                    encode::html_entity::encode(stdin.trimmed_str("input")?)
                );
            }
            EncodeCommands::Punycode => {
                println!("{}", encode::punycode::encode(stdin.trimmed_str("input")?)?);
            }
            EncodeCommands::UnicodeEscape => {
                println!(
                    "{}",
                    encode::unicode_escape::encode(stdin.trimmed_str("input")?)
                );
            }
            EncodeCommands::GzipBase64 { no_padding } => {
                println!(
                    "{}",
                    transform::gzip::compress_to_base64(stdin.trimmed_bytes()?, *no_padding)?
                );
            }
            EncodeCommands::ZlibBase64 { no_padding } => {
                println!(
                    "{}",
                    transform::compress::zlib_compress_to_base64(
                        stdin.trimmed_bytes()?,
                        *no_padding
                    )?
                );
            }
            EncodeCommands::DeflateBase64 { no_padding } => {
                println!(
                    "{}",
                    transform::compress::deflate_compress_to_base64(
                        stdin.trimmed_bytes()?,
                        *no_padding
                    )?
                );
            }
            EncodeCommands::Bzip2Base64 { no_padding } => {
                println!(
                    "{}",
                    transform::compress::bzip2_compress_to_base64(
                        stdin.trimmed_bytes()?,
                        *no_padding
                    )?
                );
            }
            EncodeCommands::XzBase64 { no_padding } => {
                println!(
                    "{}",
                    transform::compress::xz_compress_to_base64(
                        stdin.trimmed_bytes()?,
                        *no_padding
                    )?
                );
            }
            EncodeCommands::Charset { to, output } => {
                let bytes = transform::charset::encode_from_utf8(stdin.trimmed_str("input")?, *to)?;
                println!(
                    "{}",
                    transform::charset::format_output_bytes(&bytes, *output)
                );
            }
        },
        Commands::Decode { command } => match command {
            DecodeCommands::Url => {
                println!("{}", decode::url::decode(stdin.raw_str("input")?)?);
            }
            DecodeCommands::Hex => {
                println!("{}", decode::hex::decode(stdin.raw_str("input")?)?);
            }
            DecodeCommands::Base64 { url_safe } => {
                println!(
                    "{}",
                    decode::base64::decode(stdin.raw_str("input")?, *url_safe)?
                );
            }
            DecodeCommands::Base58 => {
                println!("{}", decode::base58::decode(stdin.raw_str("input")?)?);
            }
            DecodeCommands::Base85 => {
                println!("{}", decode::base85::decode(stdin.raw_str("input")?)?);
            }
            DecodeCommands::Base91 => {
                println!("{}", decode::base91::decode(stdin.raw_str("input")?)?);
            }
            DecodeCommands::Binary => {
                println!("{}", decode::binary::decode(stdin.raw_str("input")?)?);
            }
            DecodeCommands::Base32 => {
                println!("{}", decode::base32::decode(stdin.raw_str("input")?)?);
            }
            DecodeCommands::QuotedPrintable { strict } => {
                println!(
                    "{}",
                    decode::quoted_printable::decode(stdin.raw_str("input")?, *strict)?
                );
            }
            DecodeCommands::HtmlEntity => {
                println!("{}", decode::html_entity::decode(stdin.raw_str("input")?));
            }
            DecodeCommands::Punycode => {
                println!("{}", decode::punycode::decode(stdin.trimmed_str("input")?)?);
            }
            DecodeCommands::UnicodeEscape => {
                println!(
                    "{}",
                    decode::unicode_escape::decode(stdin.raw_str("input")?)?
                );
            }
            DecodeCommands::GzipBase64 => {
                println!(
                    "{}",
                    transform::gzip::decompress_from_base64(stdin.raw_str("input")?)?
                );
            }
            DecodeCommands::ZlibBase64 => {
                println!(
                    "{}",
                    transform::compress::zlib_decompress_from_base64(stdin.raw_str("input")?)?
                );
            }
            DecodeCommands::DeflateBase64 => {
                println!(
                    "{}",
                    transform::compress::deflate_decompress_from_base64(stdin.raw_str("input")?)?
                );
            }
            DecodeCommands::Bzip2Base64 => {
                println!(
                    "{}",
                    transform::compress::bzip2_decompress_from_base64(stdin.raw_str("input")?)?
                );
            }
            DecodeCommands::XzBase64 => {
                println!(
                    "{}",
                    transform::compress::xz_decompress_from_base64(stdin.raw_str("input")?)?
                );
            }
            DecodeCommands::Charset {
                from,
                input: format,
            } => {
                let bytes =
                    transform::charset::parse_input_bytes(stdin.raw_str("input")?, *format)?;
                println!("{}", transform::charset::decode_to_utf8(&bytes, *from)?);
            }
        },
        Commands::Crypto { command } => match command {
            CryptoCommands::Hash { algorithm } => {
                println!(
                    "{}",
                    transform::hash::hash(stdin.trimmed_bytes()?, *algorithm)
                );
            }
            CryptoCommands::Hmac {
                algorithm,
                key,
                hex_key,
            } => {
                println!(
                    "{}",
                    transform::checksum::hmac_digest(
                        stdin.trimmed_bytes()?,
                        key,
                        *hex_key,
                        *algorithm
                    )?
                );
            }
            CryptoCommands::Crc { algorithm } => {
                println!(
                    "{}",
                    transform::checksum::crc_digest(stdin.trimmed_bytes()?, *algorithm)
                );
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
                        stdin.trimmed_bytes()?,
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
                        stdin.raw_str("ciphertext")?,
                        key_hex,
                        nonce_hex,
                        aad
                    )?
                );
            }
            CryptoCommands::EncryptAesCbc {
                key_hex,
                iv_hex,
                no_padding,
            } => {
                println!(
                    "{}",
                    transform::symmetric::encrypt_aes_cbc_to_base64(
                        stdin.trimmed_bytes()?,
                        key_hex,
                        iv_hex,
                        *no_padding,
                    )?
                );
            }
            CryptoCommands::DecryptAesCbc { key_hex, iv_hex } => {
                println!(
                    "{}",
                    transform::symmetric::decrypt_aes_cbc_from_base64(
                        stdin.raw_str("ciphertext")?,
                        key_hex,
                        iv_hex,
                    )?
                );
            }
            CryptoCommands::EncryptAesEcb {
                key_hex,
                no_padding,
            } => {
                println!(
                    "{}",
                    transform::symmetric::encrypt_aes_ecb_to_base64(
                        stdin.trimmed_bytes()?,
                        key_hex,
                        *no_padding,
                    )?
                );
            }
            CryptoCommands::DecryptAesEcb { key_hex } => {
                println!(
                    "{}",
                    transform::symmetric::decrypt_aes_ecb_from_base64(
                        stdin.raw_str("ciphertext")?,
                        key_hex,
                    )?
                );
            }
            CryptoCommands::EncryptAesCtr {
                key_hex,
                iv_hex,
                no_padding,
            } => {
                println!(
                    "{}",
                    transform::symmetric::encrypt_aes_ctr_to_base64(
                        stdin.trimmed_bytes()?,
                        key_hex,
                        iv_hex,
                        *no_padding,
                    )?
                );
            }
            CryptoCommands::DecryptAesCtr { key_hex, iv_hex } => {
                println!(
                    "{}",
                    transform::symmetric::decrypt_aes_ctr_from_base64(
                        stdin.raw_str("ciphertext")?,
                        key_hex,
                        iv_hex,
                    )?
                );
            }
            CryptoCommands::EncryptChacha20 {
                key_hex,
                nonce_hex,
                no_padding,
            } => {
                println!(
                    "{}",
                    transform::symmetric::encrypt_chacha20_to_base64(
                        stdin.trimmed_bytes()?,
                        key_hex,
                        nonce_hex,
                        *no_padding,
                    )?
                );
            }
            CryptoCommands::DecryptChacha20 { key_hex, nonce_hex } => {
                println!(
                    "{}",
                    transform::symmetric::decrypt_chacha20_from_base64(
                        stdin.raw_str("ciphertext")?,
                        key_hex,
                        nonce_hex,
                    )?
                );
            }
            CryptoCommands::EncryptRc4 {
                key,
                hex_key,
                no_padding,
            } => {
                println!(
                    "{}",
                    transform::symmetric::encrypt_rc4_to_base64(
                        stdin.trimmed_bytes()?,
                        key,
                        *hex_key,
                        *no_padding,
                    )?
                );
            }
            CryptoCommands::DecryptRc4 { key, hex_key } => {
                println!(
                    "{}",
                    transform::symmetric::decrypt_rc4_from_base64(
                        stdin.raw_str("ciphertext")?,
                        key,
                        *hex_key,
                    )?
                );
            }
            CryptoCommands::KdfPbkdf2 {
                password,
                salt,
                hex_salt,
                iterations,
                length,
            } => {
                println!(
                    "{}",
                    transform::kdf::pbkdf2_sha256(password, salt, *hex_salt, *iterations, *length)?
                );
            }
            CryptoCommands::KdfScrypt {
                password,
                salt,
                hex_salt,
                log_n,
                r,
                p,
                length,
            } => {
                println!(
                    "{}",
                    transform::kdf::scrypt_derive(
                        password, salt, *hex_salt, *log_n, *r, *p, *length
                    )?
                );
            }
            CryptoCommands::KdfArgon2id {
                password,
                salt,
                hex_salt,
                memory_kib,
                iterations,
                parallelism,
                length,
            } => {
                println!(
                    "{}",
                    transform::kdf::argon2id_derive(
                        password,
                        salt,
                        *hex_salt,
                        *memory_kib,
                        *iterations,
                        *parallelism,
                        *length,
                    )?
                );
            }
            CryptoCommands::XorSingle { key, output_hex } => {
                let out = transform::xor::xor_with_key(stdin.trimmed_bytes()?, &[*key])?;
                println!("{}", transform::xor::format_output(&out, *output_hex));
            }
            CryptoCommands::XorRepeat {
                key,
                hex_key,
                output_hex,
            } => {
                let key_bytes = transform::xor::parse_repeat_key(key, *hex_key)?;
                let out = transform::xor::xor_with_key(stdin.trimmed_bytes()?, &key_bytes)?;
                println!("{}", transform::xor::format_output(&out, *output_hex));
            }
            CryptoCommands::XorBruteforce {
                key_bytes,
                top,
                min_score,
                prefix,
                suffix,
                word,
                raw,
            } => {
                let results = transform::xor::brute_force(
                    stdin.trimmed_bytes()?,
                    *key_bytes,
                    *top,
                    *min_score,
                    prefix.as_deref(),
                    suffix.as_deref(),
                    word,
                )?;

                for c in results {
                    if *raw {
                        println!("{}", c.plaintext);
                        continue;
                    }

                    let key_hex: String = c.key.iter().map(|b| format!("{b:02x}")).collect();
                    println!(
                        "key=0x{} key_bytes={} score={:.3} text={}",
                        key_hex,
                        c.key.len(),
                        c.score,
                        c.plaintext
                    );
                }
            }
            CryptoCommands::JwtDecode => {
                println!(
                    "{}",
                    transform::jwt::decode_unverified(stdin.require_trimmed("JWT")?)?
                );
            }
            CryptoCommands::JwtSignHs256 { key, claims } => {
                println!("{}", transform::jwt::sign_hs256(claims, key)?);
            }
            CryptoCommands::JwtVerifyHs256 { key } => {
                println!(
                    "{}",
                    transform::jwt::verify_hs256(stdin.require_trimmed("JWT")?, key)?
                );
            }
            CryptoCommands::JwtVerifyRs256 { public_key } => {
                println!(
                    "{}",
                    transform::jwt::verify_rs256(stdin.require_trimmed("JWT")?, public_key)?
                );
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
                        stdin.raw_str("input")?,
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
                    transform::unicode::normalize(stdin.trimmed_str("input")?, *form)
                );
            }
            TextCommands::Rot13 => {
                println!(
                    "{}",
                    transform::text_extra::rot13(stdin.require_trimmed("input")?)
                );
            }
            TextCommands::Rot13Bruteforce { top, min_score } => {
                for c in transform::text_extra::rot13_bruteforce(
                    stdin.require_trimmed("input")?,
                    *top,
                    *min_score,
                ) {
                    println!(
                        "shift={} score={:.3} text={}",
                        c.shift, c.score, c.plaintext
                    );
                }
            }
            TextCommands::Caesar { shift, decode } => {
                println!(
                    "{}",
                    transform::text_extra::caesar(stdin.require_trimmed("input")?, *shift, *decode)
                );
            }
            TextCommands::CaseConvert { style } => {
                println!(
                    "{}",
                    transform::text_extra::case_convert(stdin.require_trimmed("input")?, *style)
                );
            }
            TextCommands::JsonPretty => {
                println!("{}", transform::json_tools::pretty(stdin.raw_str("JSON")?)?);
            }
            TextCommands::JsonMinify => {
                println!("{}", transform::json_tools::minify(stdin.raw_str("JSON")?)?);
            }
            TextCommands::JsonPath { query } => {
                println!(
                    "{}",
                    transform::json_tools::query(stdin.raw_str("JSON")?, query)?
                );
            }
            TextCommands::XmlPretty => {
                println!("{}", transform::xml_tools::pretty(stdin.raw_str("XML")?)?);
            }
            TextCommands::XmlMinify => {
                println!("{}", transform::xml_tools::minify(stdin.raw_str("XML")?)?);
            }
            TextCommands::XPath { query } => {
                println!(
                    "{}",
                    transform::xml_tools::xpath(stdin.raw_str("XML")?, query)?
                );
            }
            TextCommands::JsonToYaml => {
                println!(
                    "{}",
                    transform::data_convert::json_to_yaml(stdin.raw_str("JSON")?)?
                );
            }
            TextCommands::YamlToJson { pretty } => {
                println!(
                    "{}",
                    transform::data_convert::yaml_to_json(stdin.raw_str("YAML")?, *pretty)?
                );
            }
            TextCommands::JsonToToml => {
                println!(
                    "{}",
                    transform::data_convert::json_to_toml(stdin.raw_str("JSON")?)?
                );
            }
            TextCommands::TomlToJson { pretty } => {
                println!(
                    "{}",
                    transform::data_convert::toml_to_json(stdin.raw_str("TOML")?, *pretty)?
                );
            }
            TextCommands::CsvToJson { pretty } => {
                println!(
                    "{}",
                    transform::data_convert::csv_to_json(stdin.raw_str("CSV")?, *pretty)?
                );
            }
            TextCommands::JsonToCsv => {
                println!(
                    "{}",
                    transform::data_convert::json_to_csv(stdin.raw_str("JSON")?)?
                );
            }
            TextCommands::UrlParse { url } => {
                println!("{}", transform::data_convert::url_parse(url)?);
            }
            TextCommands::UrlNormalize { url } => {
                println!("{}", transform::data_convert::url_normalize(url)?);
            }
            TextCommands::Defang => {
                println!(
                    "{}",
                    encode::defang::encode(stdin.trimmed_str("input")?.trim())
                );
            }
        },
        Commands::Time { command } => match command {
            TimeCommands::FromUnix { millis, value } => {
                println!("{}", transform::date::from_unix(value, *millis)?);
            }
            TimeCommands::ToUnix { millis, value } => {
                println!("{}", transform::date::to_unix(value, *millis)?);
            }
        },
        Commands::Network { command } => match command {
            NetworkCommands::CidrInfo { cidr } => {
                let cidr_value = option_or_stdin(cidr, &mut stdin, "CIDR")?;
                println!("{}", transform::network::cidr_info(&cidr_value)?);
            }
            NetworkCommands::IpToInt { ip } => {
                let ip_value = option_or_stdin(ip, &mut stdin, "IP")?;
                println!("{}", transform::network::ip_to_int(&ip_value)?);
            }
            NetworkCommands::IntToIp { v6, value } => {
                let int_value = option_or_stdin(value, &mut stdin, "integer")?;
                println!("{}", transform::network::int_to_ip(&int_value, *v6)?);
            }
            NetworkCommands::DnsToDohPacket {
                name,
                qtype,
                id,
                endpoint,
            } => {
                let domain = option_or_stdin(name, &mut stdin, "domain")?;
                let payload = transform::dns::build_doh_payload(&domain, *qtype, *id)?;
                if let Some(ep) = endpoint {
                    println!("{}", transform::dns::build_doh_url(ep, &payload));
                } else {
                    println!("{payload}");
                }
            }
            NetworkCommands::DnsPacketParse { packet, format } => {
                let packet_input = option_or_stdin(packet, &mut stdin, "packet")?;
                println!(
                    "{}",
                    transform::dns::parse_dns_packet(&packet_input, *format)?
                );
            }
            NetworkCommands::DohRequest {
                name,
                qtype,
                id,
                endpoint,
                method,
            } => {
                let domain = option_or_stdin(name, &mut stdin, "domain")?;
                let payload = transform::dns::build_doh_payload(&domain, *qtype, *id)?;
                println!(
                    "{}",
                    transform::dns::build_doh_request(endpoint, &payload, *method)?
                );
            }
        },
    }

    Ok(())
}
