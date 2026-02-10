use anyhow::{anyhow, Result};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn cidr_info(input: &str) -> Result<String> {
    let net: IpNet = input
        .trim()
        .parse()
        .map_err(|e| anyhow!("Invalid CIDR: {e}"))?;

    match net {
        IpNet::V4(v4) => cidr_info_v4(v4),
        IpNet::V6(v6) => cidr_info_v6(v6),
    }
}

fn cidr_info_v4(net: Ipv4Net) -> Result<String> {
    let network = net.network();
    let broadcast = net.broadcast();
    let prefix = net.prefix_len();

    let (first_host, last_host, usable_hosts): (Ipv4Addr, Ipv4Addr, u128) = match prefix {
        32 => (network, network, 1),
        31 => (network, broadcast, 2),
        _ => (
            u32_to_ipv4(ipv4_to_u32(network) + 1),
            u32_to_ipv4(ipv4_to_u32(broadcast) - 1),
            (1u128 << (32 - prefix)) - 2,
        ),
    };

    let mask = net.netmask();
    let wildcard = u32_to_ipv4(!ipv4_to_u32(mask));

    Ok(format!(
        "version=4\nnetwork={network}\nbroadcast={broadcast}\nfirst_host={first_host}\nlast_host={last_host}\nnetmask={mask}\nwildcard={wildcard}\nusable_hosts={usable_hosts}"
    ))
}

fn cidr_info_v6(net: Ipv6Net) -> Result<String> {
    let network = net.network();
    let prefix = net.prefix_len();
    let net_u = u128::from_be_bytes(network.octets());
    let host_bits = 128 - prefix as u32;
    let mask = if host_bits == 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    let last_u = net_u | mask;
    let last = Ipv6Addr::from(last_u.to_be_bytes());

    let usable_hosts = match prefix {
        128 => "1".to_string(),
        127 => "2".to_string(),
        _ if host_bits < 128 => format!("{}", (1u128 << host_bits) - 2),
        _ => format!("2^{host_bits} - 2"),
    };

    Ok(format!(
        "version=6\nnetwork={network}\nfirst_host={network}\nlast_host={last}\nprefix={prefix}\nusable_hosts={usable_hosts}"
    ))
}

pub fn ip_to_int(input: &str) -> Result<String> {
    let ip: IpAddr = input
        .trim()
        .parse()
        .map_err(|e| anyhow!("Invalid IP: {e}"))?;
    match ip {
        IpAddr::V4(v4) => Ok(ipv4_to_u32(v4).to_string()),
        IpAddr::V6(v6) => Ok(u128::from_be_bytes(v6.octets()).to_string()),
    }
}

pub fn int_to_ip(input: &str, v6: bool) -> Result<String> {
    if v6 {
        let n: u128 = input
            .trim()
            .parse()
            .map_err(|e| anyhow!("Invalid integer: {e}"))?;
        Ok(Ipv6Addr::from(n).to_string())
    } else {
        let n: u128 = input
            .trim()
            .parse()
            .map_err(|e| anyhow!("Invalid integer: {e}"))?;
        if n > u32::MAX as u128 {
            return Err(anyhow!("IPv4 integer out of range"));
        }
        Ok(u32_to_ipv4(n as u32).to_string())
    }
}

fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn u32_to_ipv4(v: u32) -> Ipv4Addr {
    Ipv4Addr::from(v.to_be_bytes())
}

#[cfg(test)]
mod test {
    use super::{cidr_info, int_to_ip, ip_to_int};

    #[test]
    fn cidr_24() {
        let out = cidr_info("192.168.1.10/24").unwrap();
        assert!(out.contains("version=4"));
        assert!(out.contains("network=192.168.1.0"));
        assert!(out.contains("usable_hosts=254"));
    }

    #[test]
    fn cidr_v6() {
        let out = cidr_info("2001:db8::/126").unwrap();
        assert!(out.contains("version=6"));
        assert!(out.contains("prefix=126"));
    }

    #[test]
    fn ipv4_to_int() {
        assert_eq!(ip_to_int("127.0.0.1").unwrap(), "2130706433");
    }

    #[test]
    fn int_to_ipv4() {
        assert_eq!(int_to_ip("2130706433", false).unwrap(), "127.0.0.1");
    }

    #[test]
    fn ipv6_roundtrip() {
        let n = ip_to_int("::1").unwrap();
        assert_eq!(int_to_ip(&n, true).unwrap(), "::1");
    }
}
