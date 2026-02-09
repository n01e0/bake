use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    UrlEncode {
        #[clap(long = "all", short = 'a')]
        all: bool,
    },
    UrlDecode,
    FromHex,
    ToBase32 {
        #[clap(long = "no-padding")]
        no_padding: bool,
        #[clap(long = "lower")]
        lower: bool,
    },
    FromBase32,
    Defang,
}
