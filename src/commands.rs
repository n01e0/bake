use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    UrlEncode {
        #[clap(long = "all", short = 'a')]
        all: bool,
    },
    UrlDecode,
    FromHex,
    XorSingle {
        #[clap(long = "key")]
        key: u8,
        #[clap(long = "output-hex")]
        output_hex: bool,
    },
    XorRepeat {
        #[clap(long = "key")]
        key: String,
        #[clap(long = "hex-key")]
        hex_key: bool,
        #[clap(long = "output-hex")]
        output_hex: bool,
    },
    XorBruteforceSingleByte {
        #[clap(long = "top", default_value_t = 5)]
        top: usize,
        #[clap(long = "min-score", default_value_t = 0.0)]
        min_score: f64,
    },
    Defang,
}
