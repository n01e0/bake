use clap::{Subcommand, ValueEnum};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum UnicodeForm {
    Nfc,
    Nfd,
    Nfkc,
    Nfkd,
}

#[derive(Subcommand)]
pub enum Commands {
    UrlEncode {
        #[clap(long = "all", short = 'a')]
        all: bool,
    },
    UrlDecode,
    FromHex,
    NormalizeUnicode {
        #[clap(long = "form", short = 'f', value_enum, default_value_t = UnicodeForm::Nfc)]
        form: UnicodeForm,
    },
    Defang,
}
