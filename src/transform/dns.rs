use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};

use crate::commands::{DnsPacketFormat, DnsRecordType, DohMethod};

pub fn build_doh_payload(name: &str, qtype: DnsRecordType, id: u16) -> Result<String> {
    let packet = build_dns_query_packet(name, qtype, id)?;
    Ok(general_purpose::URL_SAFE_NO_PAD.encode(packet))
}

pub fn build_doh_url(endpoint: &str, payload: &str) -> String {
    let separator = if endpoint.contains('?') { '&' } else { '?' };
    format!("{endpoint}{separator}dns={payload}")
}

pub fn build_doh_request(endpoint: &str, payload: &str, method: DohMethod) -> Result<String> {
    let packet = general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| decode_base64url_with_padding(payload))
        .map_err(|e| anyhow!("Invalid DoH payload: {e}"))?;

    match method {
        DohMethod::Get => Ok(format!(
            "GET {}\nAccept: application/dns-message",
            build_doh_url(endpoint, payload)
        )),
        DohMethod::Post => Ok(format!(
            "POST {endpoint}\nContent-Type: application/dns-message\nAccept: application/dns-message\nBody-hex: {}",
            packet.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )),
    }
}

pub fn parse_dns_packet(input: &str, format: DnsPacketFormat) -> Result<String> {
    let packet = decode_packet(input, format)?;
    if packet.len() < 12 {
        return Err(anyhow!("DNS packet too short"));
    }

    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);

    let mut offset = 12;
    let mut qname_labels = Vec::new();
    while offset < packet.len() {
        let len = packet[offset] as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        if offset + len > packet.len() {
            return Err(anyhow!("Invalid QNAME length in DNS packet"));
        }
        qname_labels.push(String::from_utf8_lossy(&packet[offset..offset + len]).to_string());
        offset += len;
    }

    if offset + 4 > packet.len() {
        return Err(anyhow!("DNS packet missing question footer"));
    }

    let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let qclass = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);

    Ok(format!(
        "id=0x{id:04x}\nflags=0x{flags:04x}\nqdcount={qdcount}\nqname={}\nqtype={}\nqclass={}",
        qname_labels.join("."),
        qtype_to_name(qtype),
        qclass
    ))
}

fn build_dns_query_packet(name: &str, qtype: DnsRecordType, id: u16) -> Result<Vec<u8>> {
    let qname = encode_qname(name)?;

    let mut packet = Vec::with_capacity(12 + qname.len() + 4);

    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());

    packet.extend_from_slice(&qname);
    packet.extend_from_slice(&qtype_to_u16(qtype).to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());

    Ok(packet)
}

fn decode_packet(input: &str, format: DnsPacketFormat) -> Result<Vec<u8>> {
    match format {
        DnsPacketFormat::Base64Url => decode_base64url_with_padding(input)
            .map_err(|e| anyhow!("Invalid base64url packet: {e}")),
        DnsPacketFormat::Base64 => {
            let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            general_purpose::STANDARD
                .decode(cleaned)
                .map_err(|e| anyhow!("Invalid base64 packet: {e}"))
        }
        DnsPacketFormat::Hex => {
            let cleaned: String = input
                .chars()
                .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
                .collect();
            if !cleaned.len().is_multiple_of(2) {
                return Err(anyhow!("Hex packet length must be even"));
            }
            let mut out = Vec::with_capacity(cleaned.len() / 2);
            for chunk in cleaned.as_bytes().chunks(2) {
                let pair = std::str::from_utf8(chunk).map_err(|e| anyhow!("Invalid hex: {e}"))?;
                let byte = u8::from_str_radix(pair, 16)
                    .map_err(|_| anyhow!("Invalid hex pair '{pair}'"))?;
                out.push(byte);
            }
            Ok(out)
        }
    }
}

fn decode_base64url_with_padding(input: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    general_purpose::URL_SAFE_NO_PAD
        .decode(&cleaned)
        .or_else(|first_err| {
            let remainder = cleaned.len() % 4;
            if remainder == 0 {
                return Err(first_err);
            }
            let padded = format!("{cleaned}{}", "=".repeat(4 - remainder));
            general_purpose::URL_SAFE_NO_PAD.decode(padded)
        })
}

fn encode_qname(name: &str) -> Result<Vec<u8>> {
    let trimmed = name.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(anyhow!("Domain name must not be empty"));
    }

    let mut out = Vec::new();
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(anyhow!("Domain contains empty label"));
        }
        if label.len() > 63 {
            return Err(anyhow!("Label too long (>{}): '{label}'", 63));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(anyhow!("Unsupported character in label '{label}'"));
        }

        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(out)
}

fn qtype_to_u16(qtype: DnsRecordType) -> u16 {
    match qtype {
        DnsRecordType::A => 1,
        DnsRecordType::Ns => 2,
        DnsRecordType::Cname => 5,
        DnsRecordType::Soa => 6,
        DnsRecordType::Ptr => 12,
        DnsRecordType::Mx => 15,
        DnsRecordType::Txt => 16,
        DnsRecordType::Aaaa => 28,
        DnsRecordType::Any => 255,
    }
}

fn qtype_to_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        255 => "ANY",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod test {
    use super::{build_doh_payload, build_doh_request, build_doh_url, parse_dns_packet};
    use crate::commands::{DnsPacketFormat, DnsRecordType, DohMethod};
    use base64::Engine;

    #[test]
    fn payload_builds_and_is_urlsafe() {
        let payload = build_doh_payload("example.com", DnsRecordType::A, 0x1234).unwrap();
        assert!(!payload.contains('='));
        assert!(!payload.contains('+'));
        assert!(!payload.contains('/'));
    }

    #[test]
    fn packet_header_and_question_match() {
        let payload = build_doh_payload("example.com", DnsRecordType::Aaaa, 0x1234).unwrap();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();

        assert_eq!(&bytes[0..2], &[0x12, 0x34]);
        assert_eq!(&bytes[2..4], &[0x01, 0x00]);
        assert_eq!(&bytes[4..6], &[0x00, 0x01]);
        assert_eq!(*bytes.last().unwrap(), 0x01);
        assert_eq!(&bytes[bytes.len() - 4..bytes.len() - 2], &[0x00, 0x1c]);
    }

    #[test]
    fn url_building() {
        let url = build_doh_url("https://dns.example/dns-query", "AAAA");
        assert_eq!(url, "https://dns.example/dns-query?dns=AAAA");

        let url2 = build_doh_url("https://dns.example/dns-query?foo=1", "BBBB");
        assert_eq!(url2, "https://dns.example/dns-query?foo=1&dns=BBBB");
    }

    #[test]
    fn parse_packet() {
        let payload = build_doh_payload("example.com", DnsRecordType::A, 0x1234).unwrap();
        let out = parse_dns_packet(&payload, DnsPacketFormat::Base64Url).unwrap();
        assert!(out.contains("qname=example.com"));
        assert!(out.contains("qtype=A"));
    }

    #[test]
    fn request_building() {
        let payload = build_doh_payload("example.com", DnsRecordType::A, 0x1234).unwrap();
        let get =
            build_doh_request("https://dns.example/dns-query", &payload, DohMethod::Get).unwrap();
        assert!(get.starts_with("GET https://dns.example/dns-query?dns="));

        let post =
            build_doh_request("https://dns.example/dns-query", &payload, DohMethod::Post).unwrap();
        assert!(post.contains("Content-Type: application/dns-message"));
    }
}
