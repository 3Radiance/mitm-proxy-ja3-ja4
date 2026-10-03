# mitm-proxy-ja3-ja4

[English](README.md) | [Русский](README.ru.md)

An HTTP MITM proxy built with Rust, `tokio`, and `btls`.

This project has been completely rewritten to leverage `btls` (BoringSSL) for advanced TLS fingerprinting capabilities. The TLS fingerprinting layer (JA3/JA4) is now fully spoofable — cipher suites, curves, signature algorithms, ALPN, record size limit, certificate compression, GREASE, extension permutation/ordering, OCSP stapling, Certificate Transparency (SCT), session tickets, ALPS, and Encrypted Client Hello (ECH, resolved live via DoH, with GREASE fallback) are all driven by a YAML profile. HTTP/2 fingerprinting (Akamai) and HTTP/1.1 header ordering/rewriting are also fully configurable. TCP (L4) fingerprinting is live too: SYN packets of upstream connections are rewritten in NFQUEUE (TTL, window size, MSS, window scale, DF flag, timestamps, exact TCP option order, per-domain marks) with automatic iptables management.

### TLS Fingerprint Spoofing Configuration

[TLS](docs/eng/TLS.md)

### HTTP/2 Fingerprint Spoofing Configuration

[HTTP/2](docs/eng/HTTP2.md)

### TCP Fingerprint Spoofing Configuration

[TCP](docs/eng/TCP.md)

## Features (Current Implementation)

* **MITM (Man-in-the-Middle)** — Transparent HTTPS interception. It uses `rcgen` to dynamically issue and sign certificates on-the-fly, caching them via `moka` for performance.

* **BoringSSL Integration** — Uses `btls` and `tokio-btls` for TLS handshake handling and MITM interception.

* **TLS Fingerprint Spoofing (JA3/JA4) — complete.** The upstream TLS connection is built entirely from a YAML profile passed via `-c` / `--config <path>` (see `config.yaml` for the format):

  * Cipher suites, in strict caller-defined order.
  * Elliptic curves.
  * Signature algorithms.
  * ALPN negotiation based on the protocol actually selected by the upstream server.
  * Record size limit.
  * Certificate compression (`brotli`, `zlib`, `zstd`) with real decompression support.
  * GREASE.
  * Exact TLS extension ordering in the ClientHello, or Chrome-style random permutation.
  * OCSP stapling, Certificate Transparency (SCT), session ticket, and ALPS (Application-Layer Protocol Settings) toggles.
  * Encrypted Client Hello (ECH) — the real ECH config is resolved live over DoH (HTTPS/SVCB record lookup) for each upstream host, using the same TLS/HTTP2 fingerprint profile for the DoH request itself; falls back to ECH GREASE (or nothing) when no config is found, independently configurable — see `TLS.md` for details.

* **Upstream-First ALPN Negotiation** — The proxy establishes and negotiates TLS with the upstream server before completing the browser-side TLS handshake. The ALPN selected by the upstream server is then used to configure the client-side TLS acceptor, preventing the browser from selecting a protocol that the upstream connection does not support.

* **HTTP/2 Fingerprint Spoofing (Akamai)** — Fully configurable HTTP/2 fingerprinting through the YAML profile:

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

* **HTTP/1.1 Header Spoofing** — Configurable header order and content for plain HTTP/1.1 upstream connections (when ALPN doesn't negotiate `h2`), mirroring the same override/removal semantics used for HTTP/2.

* **TCP Fingerprint Spoofing (L4) — complete.** Outgoing upstream connections are fingerprinted at the packet level via Linux NFQUEUE (`src/tcp_fingerprint/`):

  * SYN rewriting: TTL, window size, DF flag, MSS / window-scale values, timestamp toggle, exact TCP option order (or in-place value patching when no order is set), with checksum recalculation.
  * Established-flow queue patching TTL/DF only (IPv6 hop limit supported); every packet gets an `Accept` verdict by default so queues never stall.
  * `SO_MARK`-based routing to per-domain TCP profiles, automatic iptables management (top-inserted above tools like zapret/nfqws, deduplicated, removed on Ctrl+C shutdown) with `--queue-bypass` safety.
  * See `TCP.md` and the `tcp` block in `config.yaml`.

* **Upstream HTTP Proxy Support** — Can proxy connections through an upstream HTTP proxy via the `CONNECT` method.

* **Per-Domain Profile Routing** — Pass `-d` / `--domain <path>` with a map of domain patterns to partial profile overlays (see `domain.yaml`). Each connection is matched by SNI (exact → `*.root` → `*.label.*` → `label.*` → base profile) and served with its own TCP/TLS/HTTP2/HTTP1/upstream settings, prebuilt once at startup. Only the fields that differ from the base profile need to be specified; everything else is inherited.

* **Asynchronous** — Built on `tokio` for high-performance, non-blocking asynchronous I/O.

## Requirements

- Rust (edition 2021)
- Linux (required for the NFQUEUE L4 features)
- Root or `cap_net_admin,cap_net_raw=+eip` (for `SO_MARK`, NFQUEUE bind, and automatic iptables; without it set `"auto_iptables": false` in the `tcp` block and apply the mangle rules by hand — see `TCP.md`)
- Firefox with [Multi-Account Containers](https://addons.mozilla.org/firefox/addon/multi-account-containers/) (highly recommended for leveraging multiple fingerprints simultaneously)

## Logging

The proxy uses `tracing` with per-module filtering via `RUST_LOG`.

Examples:

```bash
RUST_LOG='H2=error' cargo run --release -- -c profile.yaml
RUST_LOG='TCP=debug,H2=error,TLS=warn' cargo run --release -- -c profile.yaml
RUST_LOG='CA=info,TLS=warn,H2=error' cargo run --release -- -c profile.yaml
```

Supported tags are the same module names used in the code: `TCP`, `HTTP`, `H1`, `H2`, `TLS`, `CA`, `ECH`, `CFG`, `IPT`, `NFQUEUE`, `Runtime`.

Log lines include a timestamp by default, so debugging sessions are easier to correlate.

## Installation & Usage

### 1. Build
```bash
git clone https://github.com/3Radiance/mitm-proxy-ja3-ja4.git
cd mitm-proxy-ja3-ja4
cargo build --release
```

### 2. Run

All settings — port, upstream proxy, and CA file paths — live in the YAML config passed via `-c` / `--config <path>`. There are no `--port` / `--upstream` CLI flags.

```yaml
config: 
  port: 9090
  upstream_proxy: "127.0.0.1:10808"
  cert: "/path/to/ca.crt"
  key: "/path/to/ca.key"
```

To run without an upstream proxy, set `upstream_proxy: null`.

```bash
cargo run --release -- --config profile.yaml
# or
cargo run --release -- -c profile.yaml
```

Upon the first run, if `cert`/`key` do not exist yet, the proxy will generate the CA files at the configured paths:
- `ca.crt` — Root CA certificate. You must import this into Firefox/your browser and trust it to identify websites.
- `ca.key` — Private key for the CA.

### 3. Per-domain overrides (optional)

```bash
cargo run --release -- -c profile.yaml -d domain.yaml
```

`domain.yaml` maps domain patterns to partial overlays — only the fields that differ from the base profile:

```yaml
"browserleaks.com":
  config:
    upstream_proxy: null
  tls:
    enable_ech: false

"*.google.com":
  tls:
    enable_ech: true

"tls.peet.ws":
  tcp:
    mark: "0x11"
    ttl: 100
    window_size: 64130
    mss: 1400
    window_scale: 7
    dont_fragment: true
    timestamp: false
    tcp_options_order:
      - mss
      - sack_perm
      - wscale
      - nop

"mail.google.*":
  tls:
    curves: 
    - X25519
    - P-256

```

Match order per connection (by SNI, case-insensitive): exact → `*.root` → `*.label.*` → `label.*` → base profile. A missing key (or `null` anywhere except `upstream_proxy`) means "inherit from base", while `"upstream_proxy": null` explicitly forces a direct connection for that domain. TCP fields (including `mark`) inherit the base profile the same way — `"mark": null` unsets the mark for that domain. Note: if the base profile sets `upstream_proxy`, no `SO_MARK` is applied at all and the TCP layer is bypassed (see `TCP.md`).

## Architecture Highlights

* `src/main.rs`: CLI entrypoint using `clap` for parsing `-c` / `--config <path>`. The YAML configuration contains the proxy port, upstream proxy, CA paths, TLS fingerprint profiles, and HTTP/2 fingerprint profiles.

### Configuration

* `src/config.rs`: YAML configuration model and parsers for all fingerprinting layers. Handles TLS settings, ECH/DoH options, HTTP/2 SETTINGS, stream priorities, header ordering, HTTP header overrides, pseudo-header ordering, and other profile-specific options.

* `src/domain.rs`: Per-domain profile overlays (`-d` / `--domain`). Partial overrides are deep-merged over the base profile once at startup; per-connection lookup is a cheap `Arc` clone with no re-allocation.

### Proxy Layer

* `src/proxy/tcp.rs`: TCP connection handling, initial HTTP `CONNECT` parsing, upstream TCP connection establishment (marked sockets via `SO_MARK` when the profile sets `mark`), SNI extraction, per-domain profile routing (SNI match with fallback to the base profile), upstream TLS negotiation, and bridging the resulting TLS connection to the client.

* `src/proxy/http.rs`: Minimal HTTP/1.x request/response parsing using `httparse`, including `CONNECT` method validation and extraction of the target `host:port`.

### TLS Fingerprinting

* `src/tls_fingerprint/cert.rs`: On-the-fly certificate generation using `rcgen` and `btls::x509`, signed by the local CA and cached in a `moka` cache.

* `src/tls_fingerprint/tls.rs`: `btls` / `tokio-btls` TLS acceptor and connector configuration, upstream TLS negotiation, client-side TLS handshake handling, and ALPN negotiation.

* `src/tls_fingerprint/helpers.rs`: Individual TLS fingerprint configuration helpers for cipher suites, curves, signature algorithms, ALPN, extension order/permutation, record size limit, certificate compression, GREASE, OCSP stapling, SCT, session tickets, and ALPS.

* `src/tls_fingerprint/compression.rs`: Certificate compression implementations for Brotli, zlib, and zstd.

* `src/tls_fingerprint/ech.rs`: Live ECH config resolution over DoH (HTTPS/SVCB record lookup, reusing the configured TLS/HTTP2 fingerprint for the DoH request itself), with GREASE fallback when no config is published for a host.

### HTTP/2 Fingerprinting

* `src/h2_fingerprint/h2.rs`: HTTP/2 connection entrypoint and connection-level request handling. Coordinates the client-side HTTP/2 connection with the configured upstream HTTP/2 connection.

* `src/h2_fingerprint/request.rs`: Incoming HTTP/2 request processing, request construction, pseudo-header ordering, HTTP header manipulation, upstream stream creation, and request/response forwarding coordination.

* `src/h2_fingerprint/request_body.rs`: Streaming HTTP/2 request body forwarding, flow-control handling, `END_STREAM` placement, and request trailers.

* `src/h2_fingerprint/response.rs`: HTTP/2 response forwarding, response body streaming, flow-control handling, `END_STREAM` handling, and response trailers.

* `src/h2_fingerprint/upstream.rs`: Creation and configuration of the upstream HTTP/2 client connection according to the active fingerprint profile.

### HTTP/1.1 Fingerprinting

* `src/h1_fingerprint/h1.rs`: HTTP/1.1 upstream request handling (used when ALPN doesn't negotiate `h2`), including configurable header order and content, built on `hyper`.

### TCP Fingerprinting

* `src/tcp_fingerprint/syn.rs`: NFQUEUE consumer for SYN packets — window/TTL/DF rewrite, TCP option rebuild from `tcp_options_order`, checksum recalculation, fwmark cleared on verdict.
* `src/tcp_fingerprint/tcp.rs`: NFQUEUE consumer for the established flow — TTL/DF only (IPv6 hop limit), everything accepted by default.
* `src/tcp_fingerprint/iptables.rs`: automatic mangle rule management — top-insert above third-party rules, dedup, shutdown cleanup.

### Module Structure

The project is divided into independent layers:

```text
src/
├── config.rs
├── domain.rs
├── main.rs
├── logging.rs
│
├── proxy/
│   ├── mod.rs
│   ├── tcp.rs
│   └── http.rs
│
├── tcp_fingerprint/
│   ├── mod.rs
│   ├── syn.rs
│   ├── tcp.rs
│   └── iptables.rs
│
├── tls_fingerprint/
│   ├── mod.rs
│   ├── cert.rs
│   ├── compression.rs
│   ├── ech.rs
│   ├── helpers.rs
│   └── tls.rs
│
├── h2_fingerprint/
│   ├── mod.rs
│   ├── h2.rs
│   ├── request.rs
│   ├── request_body.rs
│   ├── response.rs
│   └── upstream.rs
│
└── h1_fingerprint/
    ├── mod.rs
    └── h1.rs
```

The `proxy` layer handles raw TCP and HTTP `CONNECT` traffic, the `tcp_fingerprint` layer rewrites outgoing packets in NFQUEUE before they hit the wire, the `tls_fingerprint` layer handles TLS interception, TLS fingerprinting, and ECH resolution, the `h2_fingerprint` layer handles HTTP/2 fingerprinting and stream-level traffic, and the `h1_fingerprint` layer handles HTTP/1.1 header fingerprinting for upstream connections that don't negotiate `h2`. This separation keeps transport, L4, TLS, and per-protocol fingerprinting logic independent while allowing the layers to work together during a single proxied connection.

## License

MIT