use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    UrlEncode {
        #[clap(long = "all", short = 'a')]
        all: bool,
    },
    UrlDecode,
    FromHex,
    ToHex {
        #[clap(long = "delimiter", short = 'd', default_value = "")]
        delimiter: String,
        #[clap(long = "prefix", short = 'p', default_value = "")]
        prefix: String,
        #[clap(long = "upper", short = 'u')]
        upper: bool,
    },
    Defang,
}
