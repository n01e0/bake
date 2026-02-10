use clap::{Subcommand, ValueEnum};
use clap_complete::Shell;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum HmacAlgorithm {
    Sha256,
    Sha512,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CrcAlgorithm {
    Crc32,
    Crc64,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum DnsPacketFormat {
    Base64Url,
    Base64,
    Hex,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum DohMethod {
    Get,
    Post,
}

#[derive(Subcommand)]
pub enum Commands {
    Completion {
        #[clap(value_enum)]
        shell: Shell,
    },
    Encode {
        #[command(subcommand)]
        command: EncodeCommands,
    },
    Decode {
        #[command(subcommand)]
        command: DecodeCommands,
    },
    Crypto {
        #[command(subcommand)]
        command: CryptoCommands,
    },
    Text {
        #[command(subcommand)]
        command: TextCommands,
    },
    Time {
        #[command(subcommand)]
        command: TimeCommands,
    },
    Network {
        #[command(subcommand)]
        command: NetworkCommands,
    },
}

#[derive(Subcommand)]
pub enum EncodeCommands {
    Url {
        #[clap(long = "all", short = 'a')]
        all: bool,
    },
    Hex {
        #[clap(long = "delimiter", short = 'd', default_value = "")]
        delimiter: String,
        #[clap(long = "prefix", short = 'p', default_value = "")]
        prefix: String,
        #[clap(long = "upper", short = 'u')]
        upper: bool,
    },
    Base64 {
        #[clap(long = "url-safe")]
        url_safe: bool,
        #[clap(long = "no-padding")]
        no_padding: bool,
    },
    Base58,
    Base85,
    Binary {
        #[clap(long = "delimiter", short = 'd', default_value = "")]
        delimiter: String,
        #[clap(long = "prefix", short = 'p', default_value = "")]
        prefix: String,
    },
    Base32 {
        #[clap(long = "no-padding")]
        no_padding: bool,
        #[clap(long = "lower")]
        lower: bool,
    },
    HtmlEntity,
    Punycode,
    UnicodeEscape,
    GzipBase64 {
        #[clap(long = "no-padding")]
        no_padding: bool,
    },
    ZlibBase64 {
        #[clap(long = "no-padding")]
        no_padding: bool,
    },
    DeflateBase64 {
        #[clap(long = "no-padding")]
        no_padding: bool,
    },
    Bzip2Base64 {
        #[clap(long = "no-padding")]
        no_padding: bool,
    },
    XzBase64 {
        #[clap(long = "no-padding")]
        no_padding: bool,
    },
    Charset {
        #[clap(long = "to", value_enum)]
        to: Charset,
        #[clap(long = "output", value_enum, default_value_t = BinaryFormat::Hex)]
        output: BinaryFormat,
    },
}

#[derive(Subcommand)]
pub enum DecodeCommands {
    Url,
    Hex,
    Base64 {
        #[clap(long = "url-safe")]
        url_safe: bool,
    },
    Base58,
    Base85,
    Binary,
    Base32,
    HtmlEntity,
    Punycode,
    UnicodeEscape,
    GzipBase64,
    ZlibBase64,
    DeflateBase64,
    Bzip2Base64,
    XzBase64,
    Charset {
        #[clap(long = "from", value_enum)]
        from: Charset,
        #[clap(long = "input", value_enum, default_value_t = BinaryFormat::Hex)]
        input: BinaryFormat,
    },
}

#[derive(Subcommand)]
pub enum CryptoCommands {
    Hash {
        #[clap(long = "algorithm", short = 'a', value_enum, default_value_t = HashAlgorithm::Sha256)]
        algorithm: HashAlgorithm,
    },
    Hmac {
        #[clap(long = "algorithm", short = 'a', value_enum, default_value_t = HmacAlgorithm::Sha256)]
        algorithm: HmacAlgorithm,
        #[clap(long = "key")]
        key: String,
        #[clap(long = "hex-key")]
        hex_key: bool,
    },
    Crc {
        #[clap(long = "algorithm", short = 'a', value_enum, default_value_t = CrcAlgorithm::Crc32)]
        algorithm: CrcAlgorithm,
    },
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
    JwtDecode,
    JwtVerifyHs256 {
        #[clap(long = "key")]
        key: String,
    },
    JwtVerifyRs256 {
        #[clap(long = "public-key")]
        public_key: String,
    },
}

#[derive(Subcommand)]
pub enum TextCommands {
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
    NormalizeUnicode {
        #[clap(long = "form", short = 'f', value_enum, default_value_t = UnicodeForm::Nfc)]
        form: UnicodeForm,
    },
    JsonPretty,
    JsonMinify,
    JsonPath {
        query: String,
    },
    XmlPretty,
    XmlMinify,
    XPath {
        query: String,
    },
    Defang,
}

#[derive(Subcommand)]
pub enum TimeCommands {
    FromUnix {
        #[clap(long = "millis")]
        millis: bool,
    },
    ToUnix {
        #[clap(long = "millis")]
        millis: bool,
    },
}

#[derive(Subcommand)]
pub enum NetworkCommands {
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
    DnsPacketParse {
        #[clap(long = "packet")]
        packet: Option<String>,
        #[clap(long = "format", value_enum, default_value_t = DnsPacketFormat::Base64Url)]
        format: DnsPacketFormat,
    },
    DohRequest {
        #[clap(long = "name")]
        name: Option<String>,
        #[clap(long = "type", value_enum, default_value_t = DnsRecordType::A)]
        qtype: DnsRecordType,
        #[clap(long = "id", default_value_t = 0)]
        id: u16,
        #[clap(long = "endpoint")]
        endpoint: String,
        #[clap(long = "method", value_enum, default_value_t = DohMethod::Get)]
        method: DohMethod,
    },
}
