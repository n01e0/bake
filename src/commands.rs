use clap::{Subcommand, ValueEnum};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum UnicodeForm {
    Nfc,
    Nfd,
    Nfkc,
    Nfkd,
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Ptr,
    Soa,
    Txt,
    Any,
}

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
    ToBase64 {
        #[clap(long = "url-safe")]
        url_safe: bool,
        #[clap(long = "no-padding")]
        no_padding: bool,
    },
    FromBase64 {
        #[clap(long = "url-safe")]
        url_safe: bool,
    },
    ToBinary {
        #[clap(long = "delimiter", short = 'd', default_value = "")]
        delimiter: String,
        #[clap(long = "prefix", short = 'p', default_value = "")]
        prefix: String,
    },
    FromBinary,
    ToBase32 {
        #[clap(long = "no-padding")]
        no_padding: bool,
        #[clap(long = "lower")]
        lower: bool,
    },
    FromBase32,
    ToHtmlEntity,
    FromHtmlEntity,
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
    Hash {
        #[clap(long = "algorithm", short = 'a', value_enum, default_value_t = HashAlgorithm::Sha256)]
        algorithm: HashAlgorithm,
    },
    ToGzipBase64 {
        #[clap(long = "no-padding")]
        no_padding: bool,
    },
    FromGzipBase64,
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
    NormalizeUnicode {
        #[clap(long = "form", short = 'f', value_enum, default_value_t = UnicodeForm::Nfc)]
        form: UnicodeForm,
    },
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
    FromUnix {
        #[clap(long = "millis")]
        millis: bool,
    },
    ToUnix {
        #[clap(long = "millis")]
        millis: bool,
    },
    CidrInfo,
    IpToInt,
    IntToIp {
        #[clap(long = "v6")]
        v6: bool,
    },
    DnsToDohPacket {
        #[clap(long = "name")]
        name: Option<String>,
        #[clap(long = "type", value_enum, default_value_t = DnsRecordType::A)]
        qtype: DnsRecordType,
        #[clap(long = "id", default_value_t = 0)]
        id: u16,
        #[clap(long = "endpoint")]
        endpoint: Option<String>,
    },
    Defang,
}
