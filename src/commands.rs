use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    UrlEncode {
        #[clap(long = "all", short = 'a')]
        all: bool,
    },
    UrlDecode,
    FromHex,
    ToGzipBase64 {
        #[clap(long = "no-padding")]
        no_padding: bool,
    },
    FromGzipBase64,
    Defang,
}
