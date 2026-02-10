use clap::{Subcommand, ValueEnum};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Ptr,
    Soa,
    Txt,
    Any,
}

#[derive(Subcommand)]
pub enum Commands {
    UrlEncode {
        #[clap(long = "all", short = 'a')]
        all: bool,
    },
    UrlDecode,
    FromHex,
    DnsToDohPacket {
        #[clap(long = "name")]
        name: Option<String>,
        #[clap(long = "type", value_enum, default_value_t = DnsRecordType::A)]
        qtype: DnsRecordType,
        #[clap(long = "id", default_value_t = 0)]
        id: u16,
        #[clap(long = "endpoint")]
        endpoint: Option<String>,
    },
    Defang,
}
