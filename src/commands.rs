use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    UrlEncode {
        #[clap(long = "all", short = 'a')]
        all: bool,
    },
    UrlDecode,
    FromHex,
    RegexReplace {
        pattern: String,
        replacement: String,
        #[clap(long = "global", short = 'g')]
        global: bool,
        #[clap(long = "multiline")]
        multiline: bool,
        #[clap(long = "dotall")]
        dotall: bool,
    },
    Defang,
}
