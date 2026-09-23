# mitm-proxy-ja3-ja4

[English](README.md) | [Русский](README.ru.md)

An HTTP MITM proxy built with Rust, `tokio`, and `btls`.

> **Currently in MVP (Minimum Viable Product) stage.**

This project has been completely rewritten to leverage `btls` (BoringSSL) for advanced TLS fingerprinting capabilities. The TLS fingerprinting layer (JA3/JA4) is now fully spoofable — cipher suites, curves, signature algorithms, ALPN, record size limit, certificate compression, GREASE, and the exact extension order are all driven by a JSON profile. **Encrypted Client Hello (ECH) is intentionally not implemented yet** — it's on the roadmap. HTTP/2 (Akamai) and TCP (L4) fingerprinting are the next layers to be built.

## Features (Current Implementation)

- **MITM (Man-in-the-Middle)** — Transparent HTTPS interception. It uses `rcgen` to dynamically issue and sign certificates on-the-fly, caching them via `dashmap` for performance.
- **BoringSSL Integration** — Uses `btls` and `tokio-btls` for handling the TLS handshake and MITM interception.
- **TLS Fingerprint Spoofing (JA3/JA4) — complete except ECH.** The upstream connection is built entirely from a JSON profile passed via `-c` / `--config <path>` (see `example.json` for the format):
  - Cipher suites, in strict caller-defined order — see [ciphers](#supported-cipher-suites)
  - Elliptic curves — see [curves](#supported-curves)
  - Signature algorithms — see [signature algorithms](#supported-signature-algorithms)
  - ALPN, with the protocol negotiated between the browser and the proxy carried over to the upstream connection, so both ends always agree
  - Record size limit
  - Certificate compression (brotli, zlib, zstd — with real decompression, not a stub) — see [supported algorithms](#supported-certificate-compression-algorithms)
  - GREASE
  - The exact position of every TLS extension in the ClientHello — see [extension order](#supported-extension-order-values)
- **Upstream HTTP Proxy Support** — Can proxy connections through an upstream HTTP proxy via the `CONNECT` method (configurable via CLI).
- **Asynchronous** — Built on `tokio` for high-performance, non-blocking asynchronous I/O.

## Roadmap & Future Plans

The current architecture is a foundation for highly advanced fingerprint spoofing:

- **Encrypted Client Hello (ECH)**
  Not implemented yet — deferred until the rest of the fingerprinting stack is in place.
- **HTTP/2 Fingerprinting (Akamai)**
  Extend the JSON profile to cover SETTINGS frame order, pseudo-header order, and stream priorities.
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

All settings — port, upstream proxy, and CA file paths — live in the JSON config passed via `-c` / `--config <path>`. There are no `--port` / `--upstream` CLI flags.

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

- `src/main.rs`: CLI entrypoint using `clap` for parsing `-c` / `--config <path>` (the only flag; port, upstream proxy, and CA paths live inside the JSON config).
- `src/proxy/tcp.rs`: TCP connection handling, initial HTTP `CONNECT` parsing, upstream connection establishment, and bridging the raw sockets to the TLS MITM layer.
- `src/proxy/http.rs`: Minimal HTTP/1.x request/response parsing (`httparse`-based), including `CONNECT` method validation.
- `src/fingerprint/cert.rs`: On-the-fly certificate generation using `rcgen` and `btls::x509`, signed by the local CA and cached in a `DashMap`.
- `src/fingerprint/tls.rs`: `btls` acceptor/connector configuration and handshake handling (`tokio-btls`).
- `src/fingerprint/helpers.rs`: Individual TLS fingerprint setters (ciphers, curves, sigalgs, ALPN, extension order, record size limit, cert compression, GREASE).
- `src/fingerprint/compression.rs`: Certificate compression implementations (brotli, zlib, zstd).

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

## Supported Certificate Compression Algorithms

The `cert_compression` field accepts a list of algorithm names. Each one is
backed by a real decompressor (not a stub), so the handshake completes
correctly if the server actually sends a compressed certificate using one
of them:
```
brotli
zlib
zstd
```

## Supported Extension Order Values

The `extensions_order` field controls the position of each TLS extension in
the outgoing ClientHello (`SSL_CTX_set_extension_order` under the hood).
Every extension that is actually active in the handshake — enabled through
`cipher_suites`, `curves`, `signature_algorithms`, `alpn`, `cert_compression`,
`record_size_limit`, etc. — should be listed here. **If an active extension
is left out of `extensions_order`, its resulting position is undefined** —
it is not guaranteed to be dropped, appended, or placed anywhere specific,
and behavior isn't documented upstream. Always include every extension you
enable.

Full list of supported names:
```
server_name
status_request
ec_point_formats
signature_algorithms
srtp
alpn
padding
extended_master_secret
quic_transport_parameters_legacy
quic_transport_parameters_standard
cert_compression
session_ticket
supported_groups
pre_shared_key
early_data
supported_versions
cookie
psk_key_exchange_modes
certificate_authorities
signature_algorithms_cert
key_share
renegotiation_info
delegated_credentials
application_settings
application_settings_old
encrypted_client_hello
certificate_timestamp
next_proto_neg
channel_id
record_size_limit
```

## License

MIT