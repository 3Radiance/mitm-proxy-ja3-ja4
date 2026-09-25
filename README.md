# mitm-proxy-ja3-ja4

[English](README.md) | [Русский](README.ru.md)

An HTTP MITM proxy built with Rust, `tokio`, and `btls`.

> **Currently in MVP (Minimum Viable Product) stage.**

This project has been completely rewritten to leverage `btls` (BoringSSL) for advanced TLS fingerprinting capabilities. The TLS fingerprinting layer (JA3/JA4) is now fully spoofable — cipher suites, curves, signature algorithms, ALPN, record size limit, certificate compression, GREASE, and the exact extension order are all driven by a JSON profile. **Encrypted Client Hello (ECH) is intentionally not implemented yet** — it's on the roadmap. HTTP/2 (Akamai) and TCP (L4) fingerprinting are the next layers to be built.

### TLS Fingerprint Spoofing Configuration

[TLS](TLS.md)

### HTTP/2 Fingerprint Spoofing Configuration

[HTTP/2](HTTP2.md)

## Features (Current Implementation)

* **MITM (Man-in-the-Middle)** — Transparent HTTPS interception. It uses `rcgen` to dynamically issue and sign certificates on-the-fly, caching them via `dashmap` for performance.

* **BoringSSL Integration** — Uses `btls` and `tokio-btls` for TLS handshake handling and MITM interception.

* **TLS Fingerprint Spoofing (JA3/JA4) — complete except ECH.** The upstream TLS connection is built entirely from a JSON profile passed via `-c` / `--config <path>` (see `example.json` for the format):

  * Cipher suites, in strict caller-defined order.
  * Elliptic curves.
  * Signature algorithms.
  * ALPN negotiation based on the protocol actually selected by the upstream server.
  * Record size limit.
  * Certificate compression (`brotli`, `zlib`, `zstd`) with real decompression support.
  * GREASE.
  * Exact TLS extension ordering in the ClientHello.

* **Upstream-First ALPN Negotiation** — The proxy establishes and negotiates TLS with the upstream server before completing the browser-side TLS handshake. The ALPN selected by the upstream server is then used to configure the client-side TLS acceptor, preventing the browser from selecting a protocol that the upstream connection does not support.

* **HTTP/2 Fingerprint Spoofing (Akamai)** — Fully configurable HTTP/2 fingerprinting through the JSON profile:

  * HTTP/2 SETTINGS values and exact SETTINGS ordering.
  * Connection-level flow-control window updates.
  * Configurable initial stream ID with automatic calculation when priority frames are configured.
  * HTTP/2 priority frames and request header priority.
  * Configurable `END_STREAM` placement for empty requests.
  * Pseudo-header ordering.
  * HTTP header ordering.
  * HTTP header replacement, addition, and removal.
  * Streaming request and response body forwarding without buffering the complete body.
  * HTTP/2 trailers support.

* **Upstream HTTP Proxy Support** — Can proxy connections through an upstream HTTP proxy via the `CONNECT` method.

* **Asynchronous** — Built on `tokio` for high-performance, non-blocking asynchronous I/O.



### Roadmap & Future Plans

The current architecture is a foundation for highly advanced fingerprint spoofing:

* **Encrypted Client Hello (ECH)**

  Not implemented yet — deferred until the rest of the fingerprinting stack is in place.

* **L4 TCP Fingerprinting (NFQueue)**

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

* `src/main.rs`: CLI entrypoint using `clap` for parsing `-c` / `--config <path>`. The JSON configuration contains the proxy port, upstream proxy, CA paths, TLS fingerprint profiles, and HTTP/2 fingerprint profiles.

### Configuration

* `src/config.rs`: JSON configuration model and parsers for all fingerprinting layers. Handles TLS settings, HTTP/2 SETTINGS, stream priorities, header ordering, HTTP header overrides, pseudo-header ordering, and other profile-specific options.

### Proxy Layer

* `src/proxy/tcp.rs`: TCP connection handling, initial HTTP `CONNECT` parsing, upstream TCP connection establishment, SNI extraction, upstream TLS negotiation, and bridging the resulting TLS connection to the client.

* `src/proxy/http.rs`: Minimal HTTP/1.x request/response parsing using `httparse`, including `CONNECT` method validation and extraction of the target `host:port`.

### TLS Fingerprinting

* `src/tls_fingerprint/cert.rs`: On-the-fly certificate generation using `rcgen` and `btls::x509`, signed by the local CA and cached in a `DashMap`.

* `src/tls_fingerprint/tls.rs`: `btls` / `tokio-btls` TLS acceptor and connector configuration, upstream TLS negotiation, client-side TLS handshake handling, and ALPN negotiation.

* `src/tls_fingerprint/helpers.rs`: Individual TLS fingerprint configuration helpers for cipher suites, curves, signature algorithms, ALPN, extension order, record size limit, certificate compression, and GREASE.

* `src/tls_fingerprint/compression.rs`: Certificate compression implementations for Brotli, zlib, and zstd.

### HTTP/2 Fingerprinting

* `src/h2_fingerprint/h2.rs`: HTTP/2 connection entrypoint and connection-level request handling. Coordinates the client-side HTTP/2 connection with the configured upstream HTTP/2 connection.

* `src/h2_fingerprint/request.rs`: Incoming HTTP/2 request processing, request construction, pseudo-header ordering, HTTP header manipulation, upstream stream creation, and request/response forwarding coordination.

* `src/h2_fingerprint/request_body.rs`: Streaming HTTP/2 request body forwarding, flow-control handling, `END_STREAM` placement, and request trailers.

* `src/h2_fingerprint/response.rs`: HTTP/2 response forwarding, response body streaming, flow-control handling, `END_STREAM` handling, and response trailers.

* `src/h2_fingerprint/upstream.rs`: Creation and configuration of the upstream HTTP/2 client connection according to the active fingerprint profile.

### Module Structure

The project is divided into independent layers:

```text
src/
├── config.rs
├── main.rs
│
├── proxy/
│   ├── mod.rs
│   ├── tcp.rs
│   └── http.rs
│
├── tls_fingerprint/
│   ├── mod.rs
│   ├── cert.rs
│   ├── compression.rs
│   ├── helpers.rs
│   └── tls.rs
│
└── h2_fingerprint/
    ├── mod.rs
    ├── h2.rs
    ├── connection.rs
    ├── request.rs
    ├── request_body.rs
    ├── response.rs
    └── upstream.rs
```

The `proxy` layer handles raw TCP and HTTP `CONNECT` traffic, the `tls_fingerprint` layer handles TLS interception and TLS fingerprinting, and the `h2_fingerprint` layer handles HTTP/2 fingerprinting and stream-level traffic. This separation keeps transport, TLS, and HTTP/2 fingerprinting logic independent while allowing the layers to work together during a single proxied connection.

## License

MIT