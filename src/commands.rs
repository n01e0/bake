use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    UrlEncode {
        #[clap(long = "all", short = 'a')]
        all: bool,
    },
    UrlDecode,
    FromHex,
    ToBase64 {
        #[clap(long = "url-safe")]
        url_safe: bool,
        #[clap(long = "no-padding")]
        no_padding: bool,
    },
    Defang,
}
