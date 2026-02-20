# bake

CyberChef-like CLI transforms grouped by domain:

- `encode`
- `decode`
- `crypto`
- `text`
- `time`
- `network`

## Install

```bash
cargo install --path .
```

Or run directly in this repo:

```bash
cargo run -- <command>  # binary: bake
```

## Quick examples

```bash
# Encode/decode
echo -n 'hello' | bake encode base64
echo -n 'aGVsbG8=' | bake decode base64

# Crypto
echo -n 'hello' | bake crypto hash --algorithm sha256
echo -n 'hello' | bake crypto encrypt-aes-gcm \
  --key 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f \
  --nonce 1a1b1c1d1e1f202122232425
# XOR brute force (default key-bytes=1)
python3 - <<'PY' | bake crypto xor-bruteforce --word hello
import sys
pt=b'hello world'; key=0x42
sys.stdout.buffer.write(bytes([b ^ key for b in pt]))
PY

# Text
printf '{"a":1}' | bake text json-pretty
bake text url-parse --url 'https://example.com:443/path?a=1#frag'
printf 'uryyb jbeyq' | bake text rot13-bruteforce --top 5

# Time / Network (no stdin required)
bake time from-unix --value 1704067200
bake network cidr-info --cidr 2001:db8::/126
```

## Shell completion

```bash
# bash
bake completion bash > ~/.local/share/bash-completion/completions/bake

# zsh
mkdir -p ~/.zfunc
bake completion zsh > ~/.zfunc/_bake
# then ensure: fpath=(~/.zfunc $fpath) and autoload -Uz compinit && compinit

# fish
bake completion fish > ~/.config/fish/completions/bake.fish

# powershell
bake completion powershell > bake.ps1

# elvish
bake completion elvish > ~/.config/elvish/lib/bake.elv
```

## Full command reference

See [`docs/USAGE.md`](docs/USAGE.md) for full usage of every subcommand and option.

## Input behavior

- Most transform commands read from stdin.
- Commands with explicit options like `--value`, `--url`, `--cidr`, `--ip` can run without stdin.
- Encode-side stdin input trims only trailing newline characters (`\n` / `\r\n`).
