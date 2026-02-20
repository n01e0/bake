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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CaseStyle {
    Lower,
    Upper,
    Snake,
    Kebab,
    Camel,
    Pascal,
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
    Base91,
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
    QuotedPrintable {
        #[clap(long = "binary")]
        binary: bool,
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
    Base91,
    Binary,
    Base32,
    QuotedPrintable {
        #[clap(long = "strict")]
        strict: bool,
    },
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
    EncryptAesCbc {
        #[clap(long = "key")]
        key_hex: String,
        #[clap(long = "iv")]
        iv_hex: String,
        #[clap(long = "no-padding")]
        no_padding: bool,
    },
    DecryptAesCbc {
        #[clap(long = "key")]
        key_hex: String,
        #[clap(long = "iv")]
        iv_hex: String,
    },
    EncryptAesEcb {
        #[clap(long = "key")]
        key_hex: String,
        #[clap(long = "no-padding")]
        no_padding: bool,
    },
    DecryptAesEcb {
        #[clap(long = "key")]
        key_hex: String,
    },
    EncryptAesCtr {
        #[clap(long = "key")]
        key_hex: String,
        #[clap(long = "iv")]
        iv_hex: String,
        #[clap(long = "no-padding")]
        no_padding: bool,
    },
    DecryptAesCtr {
        #[clap(long = "key")]
        key_hex: String,
        #[clap(long = "iv")]
        iv_hex: String,
    },
    EncryptChacha20 {
        #[clap(long = "key")]
        key_hex: String,
        #[clap(long = "nonce")]
        nonce_hex: String,
        #[clap(long = "no-padding")]
        no_padding: bool,
    },
    DecryptChacha20 {
        #[clap(long = "key")]
        key_hex: String,
        #[clap(long = "nonce")]
        nonce_hex: String,
    },
    EncryptRc4 {
        #[clap(long = "key")]
        key: String,
        #[clap(long = "hex-key")]
        hex_key: bool,
        #[clap(long = "no-padding")]
        no_padding: bool,
    },
    DecryptRc4 {
        #[clap(long = "key")]
        key: String,
        #[clap(long = "hex-key")]
        hex_key: bool,
    },
    KdfPbkdf2 {
        #[clap(long = "password")]
        password: String,
        #[clap(long = "salt")]
        salt: String,
        #[clap(long = "hex-salt")]
        hex_salt: bool,
        #[clap(long = "iterations", default_value_t = 100_000)]
        iterations: u32,
        #[clap(long = "length", default_value_t = 32)]
        length: usize,
    },
    KdfScrypt {
        #[clap(long = "password")]
        password: String,
        #[clap(long = "salt")]
        salt: String,
        #[clap(long = "hex-salt")]
        hex_salt: bool,
        #[clap(long = "log-n", default_value_t = 15)]
        log_n: u8,
        #[clap(long = "r", default_value_t = 8)]
        r: u32,
        #[clap(long = "p", default_value_t = 1)]
        p: u32,
        #[clap(long = "length", default_value_t = 32)]
        length: usize,
    },
    KdfArgon2id {
        #[clap(long = "password")]
        password: String,
        #[clap(long = "salt")]
        salt: String,
        #[clap(long = "hex-salt")]
        hex_salt: bool,
        #[clap(long = "memory-kib", default_value_t = 19_456)]
        memory_kib: u32,
        #[clap(long = "iterations", default_value_t = 2)]
        iterations: u32,
        #[clap(long = "parallelism", default_value_t = 1)]
        parallelism: u32,
        #[clap(long = "length", default_value_t = 32)]
        length: usize,
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
    #[command(name = "xor-bruteforce", alias = "xor-bruteforce-single-byte")]
    XorBruteforce {
        #[clap(long = "key-bytes", default_value_t = 1)]
        key_bytes: usize,
        #[clap(long = "top", default_value_t = 5)]
        top: usize,
        #[clap(long = "min-score", default_value_t = 0.0)]
        min_score: f64,
        #[clap(long = "prefix")]
        prefix: Option<String>,
        #[clap(long = "suffix")]
        suffix: Option<String>,
        #[clap(long = "word")]
        word: Vec<String>,
    },
    JwtDecode,
    JwtSignHs256 {
        #[clap(long = "key")]
        key: String,
        #[clap(long = "claims")]
        claims: String,
    },
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
    Rot13,
    Rot13Bruteforce {
        #[clap(long = "top", default_value_t = 26)]
        top: usize,
        #[clap(long = "min-score", default_value_t = 0.0)]
        min_score: f64,
    },
    Caesar {
        #[clap(long = "shift")]
        shift: i8,
        #[clap(long = "decode")]
        decode: bool,
    },
    CaseConvert {
        #[clap(long = "style", value_enum)]
        style: CaseStyle,
    },
    JsonPretty,
    JsonMinify,
    JsonPath {
        query: String,
    },
    XmlPretty,
    XmlMinify,
    #[command(name = "xpath")]
    XPath {
        query: String,
    },
    JsonToYaml,
    YamlToJson {
        #[clap(long = "pretty")]
        pretty: bool,
    },
    JsonToToml,
    TomlToJson {
        #[clap(long = "pretty")]
        pretty: bool,
    },
    CsvToJson {
        #[clap(long = "pretty")]
        pretty: bool,
    },
    JsonToCsv,
    UrlParse {
        #[clap(long = "url")]
        url: String,
    },
    UrlNormalize {
        #[clap(long = "url")]
        url: String,
    },
    Defang,
}

#[derive(Subcommand)]
pub enum TimeCommands {
    FromUnix {
        #[clap(long = "millis")]
        millis: bool,
        #[clap(long = "value")]
        value: String,
    },
    ToUnix {
        #[clap(long = "millis")]
        millis: bool,
        #[clap(long = "value")]
        value: String,
    },
}

#[derive(Subcommand)]
pub enum NetworkCommands {
    CidrInfo {
        #[clap(long = "cidr")]
        cidr: Option<String>,
    },
    IpToInt {
        #[clap(long = "ip")]
        ip: Option<String>,
    },
    IntToIp {
        #[clap(long = "v6")]
        v6: bool,
        #[clap(long = "value")]
        value: Option<String>,
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
