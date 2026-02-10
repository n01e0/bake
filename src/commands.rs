use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    UrlEncode {
        #[clap(long = "all", short = 'a')]
        all: bool,
    },
    UrlDecode,
    FromHex,
    FromUnix {
        #[clap(long = "millis")]
        millis: bool,
    },
    ToUnix {
        #[clap(long = "millis")]
        millis: bool,
    },
    Defang,
}
