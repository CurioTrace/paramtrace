# ParamTrace

Fast HTTP parameter discovery for bug bounty and authorized penetration testing.
ParamTrace sends wordlist entries as parameters and flags the ones that change the
response compared to a baseline.

> **Legal notice:** only use ParamTrace on systems you own or have explicit written
> permission to test (for example, in-scope bug bounty targets). You are responsible
> for how you use it.

## How it works

1. Sends 3 requests with random fake parameters to learn the "normal" response
   (status codes and size range).
2. Tests each wordlist entry with bounded concurrency.
3. Flags a parameter when the status changes, the body size leaves the baseline range,
   or the value is reflected in the response.

## Install

```bash
git clone https://github.com/CurioTrace/paramtrace
cd paramtrace
cargo build --release
# binary: target/release/paramtrace
```

Works on Linux, macOS, Windows, and Termux (uses rustls, no OpenSSL needed).

## Usage

```bash
paramtrace -u https://example.com/search -w wordlists/common.txt
paramtrace -u https://example.com/api -w words.txt -m post -t 20
paramtrace -u https://example.com/ -w words.txt -H "Cookie: session=abc" --proxy http://127.0.0.1:8080
paramtrace -u https://example.com/ -w words.txt -o out.json -f json
```

| Flag | Description |
|------|-------------|
| `-u, --url` | Target URL |
| `-w, --wordlist` | Parameter wordlist |
| `-m, --method` | `get` (default) or `post` |
| `-t, --threads` | Concurrent requests (default 10) |
| `-H, --header` | Extra header, repeatable |
| `--timeout` | Request timeout in seconds (default 10) |
| `--delay` | Delay per request in ms |
| `--tolerance` | Ignore size differences up to N bytes (useful on dynamic pages) |
| `--value` | Value sent for each parameter |
| `--proxy` | Proxy URL (Caido, Burp) |
| `-k, --insecure` | Skip TLS verification |
| `-o, --output` / `-f, --format` | Save results as `text` or `json` |

## Limitations

- Tests one parameter per request (batching is planned).
- Pages with heavily changing content may need `--tolerance`.
- Does not follow redirects, so redirect differences count as findings.

## Wordlists

A small starter list is in `wordlists/common.txt`. For larger ones, see
[SecLists](https://github.com/danielmiessler/SecLists).

## License

MIT
