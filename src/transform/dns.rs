use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};

use crate::commands::DnsRecordType;

pub fn build_doh_payload(name: &str, qtype: DnsRecordType, id: u16) -> Result<String> {
    let packet = build_dns_query_packet(name, qtype, id)?;
    Ok(general_purpose::URL_SAFE_NO_PAD.encode(packet))
}

pub fn build_doh_url(endpoint: &str, payload: &str) -> String {
    let separator = if endpoint.contains('?') { '&' } else { '?' };
    format!("{endpoint}{separator}dns={payload}")
}

fn build_dns_query_packet(name: &str, qtype: DnsRecordType, id: u16) -> Result<Vec<u8>> {
    let qname = encode_qname(name)?;

    let mut packet = Vec::with_capacity(12 + qname.len() + 4);

    // Header
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query + RD
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question
    packet.extend_from_slice(&qname);
    packet.extend_from_slice(&qtype_to_u16(qtype).to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

    Ok(packet)
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
    out.push(0); // root terminator
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

#[cfg(test)]
mod test {
    use super::{build_doh_payload, build_doh_url};
    use crate::commands::DnsRecordType;
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

        assert_eq!(&bytes[0..2], &[0x12, 0x34]); // ID
        assert_eq!(&bytes[2..4], &[0x01, 0x00]); // flags
        assert_eq!(&bytes[4..6], &[0x00, 0x01]); // QDCOUNT
        assert_eq!(*bytes.last().unwrap(), 0x01); // class IN low byte
        assert_eq!(&bytes[bytes.len() - 4..bytes.len() - 2], &[0x00, 0x1c]); // AAAA
    }

    #[test]
    fn url_building() {
        let url = build_doh_url("https://dns.example/dns-query", "AAAA");
        assert_eq!(url, "https://dns.example/dns-query?dns=AAAA");

        let url2 = build_doh_url("https://dns.example/dns-query?foo=1", "BBBB");
        assert_eq!(url2, "https://dns.example/dns-query?foo=1&dns=BBBB");
    }

    #[test]
    fn invalid_domain() {
        let err = build_doh_payload("", DnsRecordType::A, 0)
            .unwrap_err()
            .to_string();
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn invalid_label_length() {
        let label = "a".repeat(64);
        let domain = format!("{label}.com");
        let err = build_doh_payload(&domain, DnsRecordType::A, 0)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Label too long"));
    }
}
