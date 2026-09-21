# mitm-proxy-ja3-ja4

[English](README.md) | [Русский](README.ru.md)

An HTTP MITM proxy built with Rust, `tokio`, and `BoringSSL`.

> **Currently in MVP (Minimum Viable Product) stage.**

This project has been completely rewritten to leverage `boring` (BoringSSL) for advanced TLS fingerprinting capabilities. At the moment, it functions as a transparent MITM proxy with upstream proxy support, but TLS fingerprint spoofing is currently static and uncontrolled.

## Features (Current Implementation)

- **MITM (Man-in-the-Middle)** — Transparent HTTPS interception. It uses `rcgen` to dynamically issue and sign certificates on-the-fly, caching them via `dashmap` for performance.
- **BoringSSL Integration** — Uses `boring` and `tokio-boring` for handling the TLS handshake and MITM interception.
- **Upstream HTTP Proxy Support** — Can proxy connections through an upstream HTTP proxy via the `CONNECT` method (configurable via CLI).
- **Asynchronous** — Built on `tokio` for high-performance, non-blocking asynchronous I/O.

## Roadmap & Future Plans

The current architecture is a foundation for highly advanced fingerprint spoofing:

- **Dynamic Fingerprint Spoofing (JSON Profiles)** 
  Implement granular, dynamic spoofing for TLS (JA3/JA4), HTTP/2 (Akamai), and TCP parameters. Configuration will be driven by JSON profiles (see `example.json` in the repository for the planned structure).
- **L4 TCP Fingerprinting (NFQueue)**
  Implement a Layer 4 module using Linux `nfqueue` (Netfilter Queue) to spoof TCP fingerprints, including TTL, TCP window size, MSS, window scaling, and the exact order of TCP options.

## Requirements

- Rust (edition 2021)
- Linux (for future `nfqueue` L4 features)
- Firefox with [Multi-Account Containers](https://addons.mozilla.org/firefox/addon/multi-account-containers/) (highly recommended for leveraging multiple fingerprints simultaneously)

## Installation & Usage

### 1. Build

`​`​`bash
git clone https://github.com/3Radiance/mitm-proxy-ja3-ja4.git
cd mitm-proxy-ja3-ja4
cargo build --release
`​`​`

### 2. Run

You can start the proxy specifying the port and an optional upstream HTTP proxy.

`​`​`bash
# Run on default port 9090
cargo run --release

# Run on a custom port
cargo run --release -- --port 8080

# Run with an upstream HTTP proxy
cargo run --release -- --upstream 127.0.0.1:10808
`​`​`

Upon the first run, the proxy will generate the following CA files in the current directory:
- `ca.crt` — Root CA certificate. You must import this into Firefox/your browser and trust it to identify websites.
- `ca.key` — Private key for the CA.

## Architecture Highlights

- `src/main.rs`: CLI entrypoint using `clap` for parsing `--port` and `--upstream`.
- `src/proxy/tcp.rs`: TCP connection handling, initial HTTP `CONNECT` parsing, upstream connection establishment, and bridging the raw sockets to the TLS MITM layer.
- `src/tls/cert.rs`: On-the-fly certificate generation using `rcgen` and `boring::x509`, signed by the local CA and cached in a `DashMap`.
- `src/tls/tls.rs`: BoringSSL acceptor configuration and handshake handling (`tokio-boring`).

## License

MIT
