use clap::{Subcommand, ValueEnum};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum Charset {
    Utf8,
    Utf16le,
    Utf16be,
    ShiftJis,
    EucJp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum BinaryFormat {
    Hex,
    Base64,
}

#[derive(Subcommand)]
pub enum Commands {
    UrlEncode {
        #[clap(long = "all", short = 'a')]
        all: bool,
    },
    UrlDecode,
    FromHex,
    EncodeCharset {
        #[clap(long = "to", value_enum)]
        to: Charset,
        #[clap(long = "output", value_enum, default_value_t = BinaryFormat::Hex)]
        output: BinaryFormat,
    },
    DecodeCharset {
        #[clap(long = "from", value_enum)]
        from: Charset,
        #[clap(long = "input", value_enum, default_value_t = BinaryFormat::Hex)]
        input: BinaryFormat,
    },
    Defang,
}
