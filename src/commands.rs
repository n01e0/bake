use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    UrlEncode {
        #[clap(long = "all", short = 'a')]
        all: bool,
    },
    UrlDecode,
    FromHex,
    CidrInfo,
    IpToInt,
    IntToIp {
        #[clap(long = "v6")]
        v6: bool,
    },
    Defang,
}
