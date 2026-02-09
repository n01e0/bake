use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    UrlEncode {
        #[clap(long = "all", short = 'a')]
        all: bool,
    },
    UrlDecode,
    FromHex,
    EncryptAesGcm {
        #[clap(long = "key")]
        key_hex: String,
        #[clap(long = "nonce")]
        nonce_hex: String,
        #[clap(long = "aad", default_value = "")]
        aad: String,
        #[clap(long = "no-padding")]
        no_padding: bool,
    },
    DecryptAesGcm {
        #[clap(long = "key")]
        key_hex: String,
        #[clap(long = "nonce")]
        nonce_hex: String,
        #[clap(long = "aad", default_value = "")]
        aad: String,
    },
    Defang,
}
