# mitm-proxy-ja3-ja4

**[Читать на русском →](./README.ru.md)**

HTTP MITM proxy with TLS/HTTP-2 fingerprint spoofing (JA3/JA4 + Akamai) and custom User-Agent. Built with Rust + [hudsucker](https://github.com/omjadas/hudsucker).

> ⚠️ **Without Firefox Multi-Account Containers, the whole point is lost.** Containers allow simultaneous use of different JA3/JA4 fingerprints in different tabs. Without them, the entire browser routes through a single proxy with one fingerprint — that's a red flag and useless.

## Architecture

```
Firefox Container A (VPN)  → MITM Proxy :8001 → v2rayN/SOCKS5 :10808 → VPN → Internet
Firefox Container B (Runet) → Internet
```

The proxy intercepts HTTPS traffic, dynamically generates certificates for each domain (via its own CA), modifies HTTP headers, and proxies connections through an upstream SOCKS5.

## Features

- 🔒 **MITM (Man-in-the-Middle)** — transparent HTTPS decryption with dynamic certificate generation
- 🎭 **JA3/JA4 Spoofing** — custom TLS cipher suite set for modifying the TLS fingerprint
- 🌐 **Akamai HTTP/2 Fingerprint** — window size and HTTP/2 parameter configuration
- 🧦 **Upstream SOCKS5** — proxying through v2rayN, Shadowsocks, etc.
- 📝 **User-Agent Spoofing** — header `User-Agent` substitution at the proxy level
- ⚙️ **Systemd Service** — ready integration with NixOS

## Requirements

- Rust (edition 2021)
- NixOS (for systemd integration) or any Linux
- Firefox + [Multi-Account Containers](https://addons.mozilla.org/firefox/addon/multi-account-containers/)
- [Container Proxy](https://addons.mozilla.org/firefox/addon/container-proxy/) (or equivalent) for binding proxies to containers
- v2rayN / any SOCKS5 proxy

## Installation

### 1. Clone and build

```bash
git clone https://github.com/3Radiance/mitm-proxy-ja3-ja4.git
cd mitm-proxy-ja3-ja4
cargo build --release
```

### 2. Launch

```bash
cargo run
# or
./target/release/mitm-proxy-ja3-ja4
```

On first launch, the following files will be generated:
- `ca-cert.pem` — root certificate (needs to be imported into Firefox)
- `ca-key.pem` — CA private key

## Firefox Configuration

### 1. Install extensions

- [Firefox Multi-Account Containers](https://addons.mozilla.org/firefox/addon/multi-account-containers/)
- [Container Proxy](https://addons.mozilla.org/firefox/addon/container-proxy/)

### 2. Create containers

- **VPN** — for traffic through VPN/foreign SOCKS5
- **Runet** — for traffic through a Russian IP

### 3. Assign proxy via Container Proxy

- Container **VPN** → `127.0.0.1:8001`
- Container **Runet** → `Directly`

### 4. Import CA

- Open `about:preferences#privacy` → **Certificates** → **View Certificates...**
- Tab **Authorities** → **Import...**
- Select `ca-cert.pem`
- ☑ Trust this CA to identify websites
- ☑ Trust this CA to identify software developers
- **Restart Firefox**

## Why containers specifically?

Without containers, the entire Firefox routes through a single proxy — and you get **one JA3/JA4 for all tabs**. That's a red flag:
- You logged into account A with fingerprint X
- You logged into account B with the same fingerprint X
- The site links accounts by fingerprint

**With containers:**
- Account A in VPN container → JA3 `24924417...`, IP from the Netherlands
- Account B in Runet container → JA3 `868929d9...`, IP from Moscow

Each container is an isolated environment with **its own** cookies, localStorage, proxy, and fingerprint.

## NixOS Configuration (Systemd)

Add to `configuration.nix`:

```nix
{ config, pkgs, ... }:

let
  socks5-mitm = pkgs.rustPlatform.buildRustPackage {
    pname = "socks5-tls-ja";
    version = "0.1.0";
    src = /home/YOUR_USER/mitm-proxy-ja3-ja4;
    cargoLock = {
      lockFile = /home/YOUR_USER/mitm-proxy-ja3-ja4/Cargo.lock;
    };
    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [ pkgs.openssl ];
  };
in
{
  users.users.socks5-mitm = {
    isSystemUser = true;
    group = "socks5-mitm";
    home = "/var/lib/socks5-mitm";
    createHome = true;
  };
  users.groups.socks5-mitm = {};

  systemd.services.socks5-mitm = {
    description = "SOCKS5 MITM Proxy (JA3/JA4 spoof)";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "simple";
      User = "socks5-mitm";
      Group = "socks5-mitm";
      WorkingDirectory = "/var/lib/socks5-mitm";
      ExecStart = "${socks5-mitm}/bin/socks5-tls-ja";
      Restart = "on-failure";
      RestartSec = 5;
    };
  };
}
```

After `sudo nixos-rebuild switch`:

```bash
# If migrating existing certificates:
sudo cp ~/mitm-proxy-ja3-ja4/ca-cert.pem /var/lib/socks5-mitm/
sudo cp ~/mitm-proxy-ja3-ja4/ca-key.pem /var/lib/socks5-mitm/
sudo chown socks5-mitm:socks5-mitm /var/lib/socks5-mitm/ca-cert.pem
sudo chown socks5-mitm:socks5-mitm /var/lib/socks5-mitm/ca-key.pem
sudo chmod 600 /var/lib/socks5-mitm/ca-key.pem

sudo systemctl restart socks5-mitm
sudo systemctl status socks5-mitm
```

## Customization

### User-Agent

In `src/main.rs`, in `handle_request`:

```rust
req.headers_mut().insert(
    "user-agent",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
        .parse()
        .unwrap(),
);
```

### TLS Cipher Suites (JA3/JA4)

In `build_custom_ja3_tls_config()`:

```rust
let custom_cipher_suites = vec![
    rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
    rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
];
```

### HTTP/2 Window Sizes (Akamai)

In `main()`:

```rust
client_builder.http2_initial_stream_window_size(65535);
client_builder.http2_initial_connection_window_size(15663105);
```

### Upstream SOCKS5

```rust
const SOCKS5_UPSTREAM: &str = "127.0.0.1:10808";
```

## Verification

Visit [browserleaks.com](https://browserleaks.com) and compare fingerprints:

| |  VPN Container | Runet Container |
|---|---|---|
| **JA3** | `868929d9...` | `24924417...` |
| **JA4** | `t13d1517h2...` | `t13d0612h2...` |
| **Akamai** | `6ea73faa...` | `39eaae6c...`  |

## License

MIT
