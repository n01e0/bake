# chef

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
cargo run -- <command>
```

## Quick examples

```bash
# Encode/decode
echo -n 'hello' | chef encode base64
echo -n 'aGVsbG8=' | chef decode base64

# Crypto
echo -n 'hello' | chef crypto hash --algorithm sha256
echo -n 'hello' | chef crypto encrypt-aes-gcm \
  --key 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f \
  --nonce 1a1b1c1d1e1f202122232425

# Text
printf '{"a":1}' | chef text json-pretty
chef text url-parse --url 'https://example.com:443/path?a=1#frag'

# Time / Network (no stdin required)
chef time from-unix --value 1704067200
chef network cidr-info --cidr 2001:db8::/126
```

## Shell completion

```bash
# bash
chef completion bash > ~/.local/share/bash-completion/completions/chef

# zsh
mkdir -p ~/.zfunc
chef completion zsh > ~/.zfunc/_chef
# then ensure: fpath=(~/.zfunc $fpath) and autoload -Uz compinit && compinit

# fish
chef completion fish > ~/.config/fish/completions/chef.fish

# powershell
chef completion powershell > chef.ps1

# elvish
chef completion elvish > ~/.config/elvish/lib/chef.elv
```

## Full command reference

See [`docs/USAGE.md`](docs/USAGE.md) for full usage of every subcommand and option.

## Input behavior

- Most transform commands read from stdin.
- Commands with explicit options like `--value`, `--url`, `--cidr`, `--ip` can run without stdin.
- Encode-side stdin input trims only trailing newline characters (`\n` / `\r\n`).
