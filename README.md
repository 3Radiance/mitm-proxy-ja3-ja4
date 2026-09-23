# mitm-proxy-ja3-ja4

[English](README.md) | [Русский](README.ru.md)

An HTTP MITM proxy built with Rust, `tokio`, and `btls`.

> **Currently in MVP (Minimum Viable Product) stage.**

This project has been completely rewritten to leverage `btls` (BoringSSL) for advanced TLS fingerprinting capabilities. At the moment, it functions as a transparent MITM proxy with upstream proxy support, but TLS fingerprint spoofing is currently partial.

## Features (Current Implementation)

- **MITM (Man-in-the-Middle)** — Transparent HTTPS interception. It uses `rcgen` to dynamically issue and sign certificates on-the-fly, caching them via `dashmap` for performance.
- **BoringSSL Integration** — Uses `btls` and `tokio-btls` for handling the TLS handshake and MITM interception.
- **TLS Fingerprint Spoofing** — The upstream connection sets cipher suites, elliptic curves, and signature algorithms in strict, caller-defined order, loaded from a JSON config passed via `-c` / `--config <path>` (see `example.json` in the repository for the format). See the supported lists below: [ciphers](#supported-cipher-suites), [curves](#supported-curves), [signature algorithms](#supported-signature-algorithms).
- **Upstream HTTP Proxy Support** — Can proxy connections through an upstream HTTP proxy via the `CONNECT` method (configurable via CLI).
- **Asynchronous** — Built on `tokio` for high-performance, non-blocking asynchronous I/O.

## Roadmap & Future Plans

The current architecture is a foundation for highly advanced fingerprint spoofing:

- **Dynamic Fingerprint Spoofing (JSON Profiles)**
  Extend the existing `-c` / `--config` JSON profile to also cover TLS extension order, ALPN, HTTP/2 (Akamai), and TCP parameters — currently it drives cipher suites, curves, and signature algorithms.
- **L4 TCP Fingerprinting (NFQueue)**
  Implement a Layer 4 module using Linux `nfqueue` (Netfilter Queue) to spoof TCP fingerprints, including TTL, TCP window size, MSS, window scaling, and the exact order of TCP options.

## Requirements

- Rust (edition 2021)
- Linux (for future `nfqueue` L4 features)
- Firefox with [Multi-Account Containers](https://addons.mozilla.org/firefox/addon/multi-account-containers/) (highly recommended for leveraging multiple fingerprints simultaneously)

## Installation & Usage

### 1. Build
```bash
git clone https://github.com/3Radiance/mitm-proxy-ja3-ja4.git
cd mitm-proxy-ja3-ja4
cargo build --release
```

### 2. Run

All settings — port, upstream proxy, and CA file paths — now live in the JSON config passed via `-c` / `--config <path>`. There are no more `--port` / `--upstream` CLI flags.

```json
{
  "config": {
    "port": 9090,
    "upstream_proxy": "127.0.0.1:10808",
    "cert": "/home/radiance-root/mitm-proxy-ja3-ja4/ca.crt",
    "key": "/home/radiance-root/mitm-proxy-ja3-ja4/ca.key"
  }
}
```

To run without an upstream proxy, set `"upstream_proxy": null`.

```bash
cargo run --release -- --config profile.json
# or
cargo run --release -- -c profile.json
```

Upon the first run, if `cert`/`key` do not exist yet, the proxy will generate the CA files at the configured paths:
- `ca.crt` — Root CA certificate. You must import this into Firefox/your browser and trust it to identify websites.
- `ca.key` — Private key for the CA.

## Architecture Highlights

- `src/main.rs`: CLI entrypoint using `clap` for parsing `-c` / `--config <path>` (the only flag; port, upstream proxy, and CA paths now live inside the JSON config).
- `src/proxy/tcp.rs`: TCP connection handling, initial HTTP `CONNECT` parsing, upstream connection establishment, and bridging the raw sockets to the TLS MITM layer.
- `src/tls/cert.rs`: On-the-fly certificate generation using `rcgen` and `btls::x509`, signed by the local CA and cached in a `DashMap`.
- `src/tls/tls.rs`: `btls` acceptor configuration and handshake handling (`tokio-btls`).

## Supported Cipher Suites

BoringSSL keeps TLS 1.3 and TLS 1.2 cipher suites as two separate internal
lists — they can never be interleaved in a config, and BoringSSL will always
group them as two contiguous blocks (TLS 1.3 first, then TLS 1.2) regardless
of the order they appear in `cipher_suites`. This matches how real browsers
build their ClientHello, so it isn't a limitation you need to work around.

Naming also differs between the two: TLS 1.3 suites use IANA-style
`TLS_<AEAD>_<HASH>` names, while TLS 1.2 suites must be passed using
OpenSSL-style short names (`ECDHE-ECDSA-AES128-GCM-SHA256`) — the
`TLS_ECDHE_..._WITH_...` long form is **not** accepted for TLS 1.2 suites.

### TLS 1.3
```
TLS_AES_128_GCM_SHA256
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
```

### TLS 1.2
```
ECDHE-ECDSA-AES128-GCM-SHA256
ECDHE-ECDSA-AES256-GCM-SHA384
ECDHE-RSA-AES128-GCM-SHA256
ECDHE-RSA-AES256-GCM-SHA384
ECDHE-ECDSA-CHACHA20-POLY1305
ECDHE-RSA-CHACHA20-POLY1305
ECDHE-ECDSA-AES128-SHA
ECDHE-RSA-AES128-SHA
ECDHE-RSA-AES128-SHA256
ECDHE-ECDSA-AES256-SHA
ECDHE-RSA-AES256-SHA
TLS_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_256_GCM_SHA384
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_3DES_EDE_CBC_SHA
TLS_PSK_WITH_AES_128_CBC_SHA
TLS_PSK_WITH_AES_256_CBC_SHA
ECDHE-PSK-AES128-CBC-SHA
ECDHE-PSK-AES256-CBC-SHA
ECDHE-PSK-CHACHA20-POLY1305
```
## Supported Curves

Full list (BoringSSL):
```
P-256
P-384
P-521
X25519
X25519Kyber768Draft00
X25519MLKEM768
MLKEM1024
```

## Supported Signature Algorithms

Full list (BoringSSL):
```
rsa_pkcs1_md5_sha1
rsa_pkcs1_sha1
rsa_pkcs1_sha256
rsa_pkcs1_sha256_legacy
rsa_pkcs1_sha384
rsa_pkcs1_sha512
ecdsa_secp256r1_sha256
ecdsa_secp384r1_sha384
ecdsa_secp521r1_sha512
rsa_pss_rsae_sha256
rsa_pss_rsae_sha384
rsa_pss_rsae_sha512
ed25519
```

## License

MIT