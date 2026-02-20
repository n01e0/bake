# chef Usage

CLI for encoding/decoding, crypto, text transforms, time/network utilities.

## Basic patterns

- Commands that transform content usually read from stdin.
- Commands with explicit value options (e.g. `--value`, `--url`, `--cidr`) do not require stdin.
- Encode-side stdin input trims trailing `\n`/`\r\n` only.

```bash
echo -n 'hello' | chef encode base64
chef time from-unix --value 1704067200
chef text url-parse --url 'https://example.com:443/a?x=1#f'
```

## Top-level commands

```text
Usage: chef <COMMAND>

Commands:
  completion  
  encode      
  decode      
  crypto      
  text        
  time        
  network     
  help        Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## `completion`

```text
Usage: chef completion <SHELL>

Arguments:
  <SHELL>  [possible values: bash, elvish, fish, powershell, zsh]

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## `encode`

```text
Usage: chef encode <COMMAND>

Commands:
  url               
  hex               
  base64            
  base58            
  base85            
  base91            
  binary            
  base32            
  quoted-printable  
  html-entity       
  punycode          
  unicode-escape    
  gzip-base64       
  zlib-base64       
  deflate-base64    
  bzip2-base64      
  xz-base64         
  charset           
  help              Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `encode url`

```text
Usage: chef encode url [OPTIONS]

Options:
  -a, --all      
  -h, --help     Print help
  -V, --version  Print version
```

### `encode hex`

```text
Usage: chef encode hex [OPTIONS]

Options:
  -d, --delimiter <DELIMITER>  [default: ]
  -p, --prefix <PREFIX>        [default: ]
  -u, --upper                  
  -h, --help                   Print help
  -V, --version                Print version
```

### `encode base64`

```text
Usage: chef encode base64 [OPTIONS]

Options:
      --url-safe    
      --no-padding  
  -h, --help        Print help
  -V, --version     Print version
```

### `encode base58`

```text
Usage: chef encode base58

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `encode base85`

```text
Usage: chef encode base85

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `encode base91`

```text
Usage: chef encode base91

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `encode binary`

```text
Usage: chef encode binary [OPTIONS]

Options:
  -d, --delimiter <DELIMITER>  [default: ]
  -p, --prefix <PREFIX>        [default: ]
  -h, --help                   Print help
  -V, --version                Print version
```

### `encode base32`

```text
Usage: chef encode base32 [OPTIONS]

Options:
      --no-padding  
      --lower       
  -h, --help        Print help
  -V, --version     Print version
```

### `encode quoted-printable`

```text
Usage: chef encode quoted-printable [OPTIONS]

Options:
      --binary   
  -h, --help     Print help
  -V, --version  Print version
```

### `encode html-entity`

```text
Usage: chef encode html-entity

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `encode punycode`

```text
Usage: chef encode punycode

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `encode unicode-escape`

```text
Usage: chef encode unicode-escape

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `encode gzip-base64`

```text
Usage: chef encode gzip-base64 [OPTIONS]

Options:
      --no-padding  
  -h, --help        Print help
  -V, --version     Print version
```

### `encode zlib-base64`

```text
Usage: chef encode zlib-base64 [OPTIONS]

Options:
      --no-padding  
  -h, --help        Print help
  -V, --version     Print version
```

### `encode deflate-base64`

```text
Usage: chef encode deflate-base64 [OPTIONS]

Options:
      --no-padding  
  -h, --help        Print help
  -V, --version     Print version
```

### `encode bzip2-base64`

```text
Usage: chef encode bzip2-base64 [OPTIONS]

Options:
      --no-padding  
  -h, --help        Print help
  -V, --version     Print version
```

### `encode xz-base64`

```text
Usage: chef encode xz-base64 [OPTIONS]

Options:
      --no-padding  
  -h, --help        Print help
  -V, --version     Print version
```

### `encode charset`

```text
Usage: chef encode charset [OPTIONS] --to <TO>

Options:
      --to <TO>          [possible values: utf8, utf16le, utf16be, shift-jis, euc-jp]
      --output <OUTPUT>  [default: hex] [possible values: hex, base64]
  -h, --help             Print help
  -V, --version          Print version
```

## `decode`

```text
Usage: chef decode <COMMAND>

Commands:
  url               
  hex               
  base64            
  base58            
  base85            
  base91            
  binary            
  base32            
  quoted-printable  
  html-entity       
  punycode          
  unicode-escape    
  gzip-base64       
  zlib-base64       
  deflate-base64    
  bzip2-base64      
  xz-base64         
  charset           
  help              Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `decode url`

```text
Usage: chef decode url

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `decode hex`

```text
Usage: chef decode hex

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `decode base64`

```text
Usage: chef decode base64 [OPTIONS]

Options:
      --url-safe  
  -h, --help      Print help
  -V, --version   Print version
```

### `decode base58`

```text
Usage: chef decode base58

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `decode base85`

```text
Usage: chef decode base85

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `decode base91`

```text
Usage: chef decode base91

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `decode binary`

```text
Usage: chef decode binary

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `decode base32`

```text
Usage: chef decode base32

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `decode quoted-printable`

```text
Usage: chef decode quoted-printable [OPTIONS]

Options:
      --strict   
  -h, --help     Print help
  -V, --version  Print version
```

### `decode html-entity`

```text
Usage: chef decode html-entity

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `decode punycode`

```text
Usage: chef decode punycode

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `decode unicode-escape`

```text
Usage: chef decode unicode-escape

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `decode gzip-base64`

```text
Usage: chef decode gzip-base64

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `decode zlib-base64`

```text
Usage: chef decode zlib-base64

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `decode deflate-base64`

```text
Usage: chef decode deflate-base64

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `decode bzip2-base64`

```text
Usage: chef decode bzip2-base64

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `decode xz-base64`

```text
Usage: chef decode xz-base64

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `decode charset`

```text
Usage: chef decode charset [OPTIONS] --from <FROM>

Options:
      --from <FROM>    [possible values: utf8, utf16le, utf16be, shift-jis, euc-jp]
      --input <INPUT>  [default: hex] [possible values: hex, base64]
  -h, --help           Print help
  -V, --version        Print version
```

## `crypto`

```text
Usage: chef crypto <COMMAND>

Commands:
  hash                        
  hmac                        
  crc                         
  encrypt-aes-gcm             
  decrypt-aes-gcm             
  encrypt-aes-cbc             
  decrypt-aes-cbc             
  encrypt-aes-ecb             
  decrypt-aes-ecb             
  encrypt-aes-ctr             
  decrypt-aes-ctr             
  encrypt-chacha20            
  decrypt-chacha20            
  encrypt-rc4                 
  decrypt-rc4                 
  kdf-pbkdf2                  
  kdf-scrypt                  
  kdf-argon2id                
  xor-single                  
  xor-repeat                  
  xor-bruteforce-single-byte  
  jwt-decode                  
  jwt-sign-hs256              
  jwt-verify-hs256            
  jwt-verify-rs256            
  help                        Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `crypto hash`

```text
Usage: chef crypto hash [OPTIONS]

Options:
  -a, --algorithm <ALGORITHM>  [default: sha256] [possible values: md5, sha1, sha256, sha512]
  -h, --help                   Print help
  -V, --version                Print version
```

### `crypto hmac`

```text
Usage: chef crypto hmac [OPTIONS] --key <KEY>

Options:
  -a, --algorithm <ALGORITHM>  [default: sha256] [possible values: sha256, sha512]
      --key <KEY>              
      --hex-key                
  -h, --help                   Print help
  -V, --version                Print version
```

### `crypto crc`

```text
Usage: chef crypto crc [OPTIONS]

Options:
  -a, --algorithm <ALGORITHM>  [default: crc32] [possible values: crc32, crc64]
  -h, --help                   Print help
  -V, --version                Print version
```

### `crypto encrypt-aes-gcm`

```text
Usage: chef crypto encrypt-aes-gcm [OPTIONS] --key <KEY_HEX> --nonce <NONCE_HEX>

Options:
      --key <KEY_HEX>      
      --nonce <NONCE_HEX>  
      --aad <AAD>          [default: ]
      --no-padding         
  -h, --help               Print help
  -V, --version            Print version
```

### `crypto decrypt-aes-gcm`

```text
Usage: chef crypto decrypt-aes-gcm [OPTIONS] --key <KEY_HEX> --nonce <NONCE_HEX>

Options:
      --key <KEY_HEX>      
      --nonce <NONCE_HEX>  
      --aad <AAD>          [default: ]
  -h, --help               Print help
  -V, --version            Print version
```

### `crypto encrypt-aes-cbc`

```text
Usage: chef crypto encrypt-aes-cbc [OPTIONS] --key <KEY_HEX> --iv <IV_HEX>

Options:
      --key <KEY_HEX>  
      --iv <IV_HEX>    
      --no-padding     
  -h, --help           Print help
  -V, --version        Print version
```

### `crypto decrypt-aes-cbc`

```text
Usage: chef crypto decrypt-aes-cbc --key <KEY_HEX> --iv <IV_HEX>

Options:
      --key <KEY_HEX>  
      --iv <IV_HEX>    
  -h, --help           Print help
  -V, --version        Print version
```

### `crypto encrypt-aes-ecb`

```text
Usage: chef crypto encrypt-aes-ecb [OPTIONS] --key <KEY_HEX>

Options:
      --key <KEY_HEX>  
      --no-padding     
  -h, --help           Print help
  -V, --version        Print version
```

### `crypto decrypt-aes-ecb`

```text
Usage: chef crypto decrypt-aes-ecb --key <KEY_HEX>

Options:
      --key <KEY_HEX>  
  -h, --help           Print help
  -V, --version        Print version
```

### `crypto encrypt-aes-ctr`

```text
Usage: chef crypto encrypt-aes-ctr [OPTIONS] --key <KEY_HEX> --iv <IV_HEX>

Options:
      --key <KEY_HEX>  
      --iv <IV_HEX>    
      --no-padding     
  -h, --help           Print help
  -V, --version        Print version
```

### `crypto decrypt-aes-ctr`

```text
Usage: chef crypto decrypt-aes-ctr --key <KEY_HEX> --iv <IV_HEX>

Options:
      --key <KEY_HEX>  
      --iv <IV_HEX>    
  -h, --help           Print help
  -V, --version        Print version
```

### `crypto encrypt-chacha20`

```text
Usage: chef crypto encrypt-chacha20 [OPTIONS] --key <KEY_HEX> --nonce <NONCE_HEX>

Options:
      --key <KEY_HEX>      
      --nonce <NONCE_HEX>  
      --no-padding         
  -h, --help               Print help
  -V, --version            Print version
```

### `crypto decrypt-chacha20`

```text
Usage: chef crypto decrypt-chacha20 --key <KEY_HEX> --nonce <NONCE_HEX>

Options:
      --key <KEY_HEX>      
      --nonce <NONCE_HEX>  
  -h, --help               Print help
  -V, --version            Print version
```

### `crypto encrypt-rc4`

```text
Usage: chef crypto encrypt-rc4 [OPTIONS] --key <KEY>

Options:
      --key <KEY>   
      --hex-key     
      --no-padding  
  -h, --help        Print help
  -V, --version     Print version
```

### `crypto decrypt-rc4`

```text
Usage: chef crypto decrypt-rc4 [OPTIONS] --key <KEY>

Options:
      --key <KEY>  
      --hex-key    
  -h, --help       Print help
  -V, --version    Print version
```

### `crypto kdf-pbkdf2`

```text
Usage: chef crypto kdf-pbkdf2 [OPTIONS] --password <PASSWORD> --salt <SALT>

Options:
      --password <PASSWORD>      
      --salt <SALT>              
      --hex-salt                 
      --iterations <ITERATIONS>  [default: 100000]
      --length <LENGTH>          [default: 32]
  -h, --help                     Print help
  -V, --version                  Print version
```

### `crypto kdf-scrypt`

```text
Usage: chef crypto kdf-scrypt [OPTIONS] --password <PASSWORD> --salt <SALT>

Options:
      --password <PASSWORD>  
      --salt <SALT>          
      --hex-salt             
      --log-n <LOG_N>        [default: 15]
      --r <R>                [default: 8]
      --p <P>                [default: 1]
      --length <LENGTH>      [default: 32]
  -h, --help                 Print help
  -V, --version              Print version
```

### `crypto kdf-argon2id`

```text
Usage: chef crypto kdf-argon2id [OPTIONS] --password <PASSWORD> --salt <SALT>

Options:
      --password <PASSWORD>        
      --salt <SALT>                
      --hex-salt                   
      --memory-kib <MEMORY_KIB>    [default: 19456]
      --iterations <ITERATIONS>    [default: 2]
      --parallelism <PARALLELISM>  [default: 1]
      --length <LENGTH>            [default: 32]
  -h, --help                       Print help
  -V, --version                    Print version
```

### `crypto xor-single`

```text
Usage: chef crypto xor-single [OPTIONS] --key <KEY>

Options:
      --key <KEY>   
      --output-hex  
  -h, --help        Print help
  -V, --version     Print version
```

### `crypto xor-repeat`

```text
Usage: chef crypto xor-repeat [OPTIONS] --key <KEY>

Options:
      --key <KEY>   
      --hex-key     
      --output-hex  
  -h, --help        Print help
  -V, --version     Print version
```

### `crypto xor-bruteforce-single-byte`

```text
Usage: chef crypto xor-bruteforce-single-byte [OPTIONS]

Options:
      --top <TOP>              [default: 5]
      --min-score <MIN_SCORE>  [default: 0]
  -h, --help                   Print help
  -V, --version                Print version
```

### `crypto jwt-decode`

```text
Usage: chef crypto jwt-decode

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `crypto jwt-sign-hs256`

```text
Usage: chef crypto jwt-sign-hs256 --key <KEY> --claims <CLAIMS>

Options:
      --key <KEY>        
      --claims <CLAIMS>  
  -h, --help             Print help
  -V, --version          Print version
```

### `crypto jwt-verify-hs256`

```text
Usage: chef crypto jwt-verify-hs256 --key <KEY>

Options:
      --key <KEY>  
  -h, --help       Print help
  -V, --version    Print version
```

### `crypto jwt-verify-rs256`

```text
Usage: chef crypto jwt-verify-rs256 --public-key <PUBLIC_KEY>

Options:
      --public-key <PUBLIC_KEY>  
  -h, --help                     Print help
  -V, --version                  Print version
```

## `text`

```text
Usage: chef text <COMMAND>

Commands:
  regex-replace      
  normalize-unicode  
  rot13              
  rot13-bruteforce   
  caesar             
  case-convert       
  json-pretty        
  json-minify        
  json-path          
  xml-pretty         
  xml-minify         
  xpath              
  json-to-yaml       
  yaml-to-json       
  json-to-toml       
  toml-to-json       
  csv-to-json        
  json-to-csv        
  url-parse          
  url-normalize      
  defang             
  help               Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `text regex-replace`

```text
Usage: chef text regex-replace [OPTIONS] <PATTERN> <REPLACEMENT>

Arguments:
  <PATTERN>      
  <REPLACEMENT>  

Options:
  -g, --global     
      --multiline  
      --dotall     
  -h, --help       Print help
  -V, --version    Print version
```

### `text normalize-unicode`

```text
Usage: chef text normalize-unicode [OPTIONS]

Options:
  -f, --form <FORM>  [default: nfc] [possible values: nfc, nfd, nfkc, nfkd]
  -h, --help         Print help
  -V, --version      Print version
```

### `text rot13`

```text
Usage: chef text rot13

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `text rot13-bruteforce`

```text
Usage: chef text rot13-bruteforce [OPTIONS]

Options:
      --top <TOP>              [default: 26]
      --min-score <MIN_SCORE>  [default: 0]
  -h, --help                   Print help
  -V, --version                Print version
```

### `text caesar`

```text
Usage: chef text caesar [OPTIONS] --shift <SHIFT>

Options:
      --shift <SHIFT>  
      --decode         
  -h, --help           Print help
  -V, --version        Print version
```

### `text case-convert`

```text
Usage: chef text case-convert --style <STYLE>

Options:
      --style <STYLE>  [possible values: lower, upper, snake, kebab, camel, pascal]
  -h, --help           Print help
  -V, --version        Print version
```

### `text json-pretty`

```text
Usage: chef text json-pretty

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `text json-minify`

```text
Usage: chef text json-minify

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `text json-path`

```text
Usage: chef text json-path <QUERY>

Arguments:
  <QUERY>  

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `text xml-pretty`

```text
Usage: chef text xml-pretty

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `text xml-minify`

```text
Usage: chef text xml-minify

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `text xpath`

```text
Usage: chef text xpath <QUERY>

Arguments:
  <QUERY>  

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `text json-to-yaml`

```text
Usage: chef text json-to-yaml

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `text yaml-to-json`

```text
Usage: chef text yaml-to-json [OPTIONS]

Options:
      --pretty   
  -h, --help     Print help
  -V, --version  Print version
```

### `text json-to-toml`

```text
Usage: chef text json-to-toml

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `text toml-to-json`

```text
Usage: chef text toml-to-json [OPTIONS]

Options:
      --pretty   
  -h, --help     Print help
  -V, --version  Print version
```

### `text csv-to-json`

```text
Usage: chef text csv-to-json [OPTIONS]

Options:
      --pretty   
  -h, --help     Print help
  -V, --version  Print version
```

### `text json-to-csv`

```text
Usage: chef text json-to-csv

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `text url-parse`

```text
Usage: chef text url-parse --url <URL>

Options:
      --url <URL>  
  -h, --help       Print help
  -V, --version    Print version
```

### `text url-normalize`

```text
Usage: chef text url-normalize --url <URL>

Options:
      --url <URL>  
  -h, --help       Print help
  -V, --version    Print version
```

### `text defang`

```text
Usage: chef text defang

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## `time`

```text
Usage: chef time <COMMAND>

Commands:
  from-unix  
  to-unix    
  help       Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `time from-unix`

```text
Usage: chef time from-unix [OPTIONS] --value <VALUE>

Options:
      --millis         
      --value <VALUE>  
  -h, --help           Print help
  -V, --version        Print version
```

### `time to-unix`

```text
Usage: chef time to-unix [OPTIONS] --value <VALUE>

Options:
      --millis         
      --value <VALUE>  
  -h, --help           Print help
  -V, --version        Print version
```

## `network`

```text
Usage: chef network <COMMAND>

Commands:
  cidr-info          
  ip-to-int          
  int-to-ip          
  dns-to-doh-packet  
  dns-packet-parse   
  doh-request        
  help               Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `network cidr-info`

```text
Usage: chef network cidr-info [OPTIONS]

Options:
      --cidr <CIDR>  
  -h, --help         Print help
  -V, --version      Print version
```

### `network ip-to-int`

```text
Usage: chef network ip-to-int [OPTIONS]

Options:
      --ip <IP>  
  -h, --help     Print help
  -V, --version  Print version
```

### `network int-to-ip`

```text
Usage: chef network int-to-ip [OPTIONS]

Options:
      --v6             
      --value <VALUE>  
  -h, --help           Print help
  -V, --version        Print version
```

### `network dns-to-doh-packet`

```text
Usage: chef network dns-to-doh-packet [OPTIONS]

Options:
      --name <NAME>          
      --type <QTYPE>         [default: a] [possible values: a, aaaa, cname, mx, ns, ptr, soa, txt, any]
      --id <ID>              [default: 0]
      --endpoint <ENDPOINT>  
  -h, --help                 Print help
  -V, --version              Print version
```

### `network dns-packet-parse`

```text
Usage: chef network dns-packet-parse [OPTIONS]

Options:
      --packet <PACKET>  
      --format <FORMAT>  [default: base64-url] [possible values: base64-url, base64, hex]
  -h, --help             Print help
  -V, --version          Print version
```

### `network doh-request`

```text
Usage: chef network doh-request [OPTIONS] --endpoint <ENDPOINT>

Options:
      --name <NAME>          
      --type <QTYPE>         [default: a] [possible values: a, aaaa, cname, mx, ns, ptr, soa, txt, any]
      --id <ID>              [default: 0]
      --endpoint <ENDPOINT>  
      --method <METHOD>      [default: get] [possible values: get, post]
  -h, --help                 Print help
  -V, --version              Print version
```
