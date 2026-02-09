use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    UrlEncode {
        #[clap(long = "all", short = 'a')]
        all: bool,
    },
    UrlDecode,
    FromHex,
    FromBase64 {
        #[clap(long = "url-safe")]
        url_safe: bool,
    },
    Defang,
}
