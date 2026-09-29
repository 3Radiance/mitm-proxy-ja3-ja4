# TLS Fingerprint Spoofing (JA3/JA4)

[English](TLS.md) | [Русский](TLS.ru.md)

The upstream TLS connection is built entirely from the JSON profile:
every byte of the ClientHello that fingerprinting sees — cipher order,
extensions and their order, curves, signature algorithms, ALPN, GREASE,
compression, ECH — is caller-controlled. The stack is BoringSSL via
`btls` / `tokio-btls` (`src/tls_fingerprint/`).

## Connection flow

```
browser ──ClientHello──▶ proxy
                            1. parse CONNECT, extract SNI/host
                            2. route profile by SNI (base or domain overlay)
                            3. open upstream TCP (marked socket, see TCP.md)
                            4. TLS handshake upstream FIRST, with the profile
                            5. take upstream's ALPN, build client-side acceptor
browser ◀──ServerHello (forged cert, upstream's ALPN)── proxy
```

Upstream-first matters: the ALPN the real server selects dictates which
client-side handshake the browser gets, so the browser can never negotiate
a protocol the upstream connection doesn't speak. The client side uses a
`mozilla_intermediate` acceptor with an on-the-fly certificate (`rcgen`,
signed by the local CA, cached in `moka`) and an ALPN select callback
replaying the upstream's choice (defaulting to `http/1.1`).

The upstream `SslConnector` is assembled in
`create_ssl_acceptor_upstream` (`src/tls_fingerprint/tls.rs`) in this
order: cipher suites → ALPN → curves → signature algorithms → record
size limit → certificate compression → GREASE → extension
permutation/order → OCSP → SCT → session ticket → delegated credentials
→ extension order → ALPS → ECH. Verification uses the Chromium root
store. Handshake timeout is 5 seconds.

## Configuration (`tls` block)

```json
"tls": {
    "cipher_suites": ["TLS_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256", "..."],
    "alpn": ["h2", "http/1.1"],
    "curves": ["X25519", "P-256", "P-384"],
    "signature_algorithms": ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "..."],
    "extensions_order": null,
    "cert_compression": ["brotli"],
    "permute_extensions": false,
    "status_request": false,
    "signed_certificate_timestamp": false,
    "alps": false,
    "session_ticket": false,
    "grease_enabled": false,
    "enable_ech": true,
    "enable_ech_grease": false,
    "delegated_credentials": null,
    "record_size_limit": null,
    "doh": ["dns.google"]
}
```

### `cipher_suites` — strict order, two blocks

The list is joined with `:` and passed to `set_cipher_list`, with
`set_preserve_tls13_cipher_list(true)` so your order survives verbatim.
BoringSSL keeps TLS 1.3 and TLS 1.2 suites as two separate internal
lists — they can never be interleaved, and BoringSSL always emits them
as two contiguous blocks (TLS 1.3 first, then TLS 1.2) regardless of how
they are mixed in the config. Real browsers build their ClientHello the
same way, so this is not a limitation to work around.

Naming differs per version: TLS 1.3 suites use IANA-style
`TLS_<AEAD>_<HASH>` names, TLS 1.2 suites must use OpenSSL-style short
names (`ECDHE-ECDSA-AES128-GCM-SHA256`) — the `TLS_ECDHE_..._WITH_...`
long form is **not** accepted for TLS 1.2.

TLS 1.3:
```
TLS_AES_128_GCM_SHA256
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
```

TLS 1.2:
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

### `alpn` — protocol list

Joined into length-prefixed wire format (`encode_alpn_wire`) and offered
to the server. The server's choice is what the whole connection — and the
client-side handshake — ends up speaking.

### `curves` — supported groups, in order

Passed to `set_curves_list`. Full BoringSSL vocabulary:
```
P-256
P-384
P-521
X25519
X25519Kyber768Draft00
X25519MLKEM768
MLKEM1024
```

### `signature_algorithms` — in order

Passed to `set_sigalgs_list`. Full vocabulary:
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

### `extensions_order` — exact extension positions

Controls the position of each TLS extension in the outgoing ClientHello
(`set_extension_permutation` under the hood). Every extension that is
actually active in the handshake — enabled via `cipher_suites`, `curves`,
`signature_algorithms`, `alpn`, `cert_compression`, `record_size_limit`,
etc. — should be listed here. **If an active extension is left out, its
resulting position is undefined** — not guaranteed dropped, appended, or
placed anywhere specific; upstream documents nothing here. Always list
everything you enable.

Supported names (several accept aliases):

```
server_name
status_request
ec_point_formats
signature_algorithms
srtp
alpn
padding
signed_certificate_timestamp (or certificate_timestamp)
extended_master_secret
quic_transport_parameters_legacy
quic_transport_parameters_standard (or quic_transport_parameters)
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
encrypted_client_hello (or ech)
next_proto_neg (or npn)
channel_id
record_size_limit
```

`renegotiation_info` (RFC 5746) is not toggleable and needs no toggle —
BoringSSL always sends it like every modern browser; it only needs a
position in this list.

### `cert_compression` — with real decompressors

Each name registers a working decompressor, so the handshake completes
even if the server actually sends a compressed certificate with it:

```
brotli
zlib
zstd
```

Unknown names are a hard error, not a silent skip.

### Boolean toggles

- **`permute_extensions`** — randomizes extension order on every
  handshake (Chrome behavior). **Never combine with a populated
  `extensions_order`** — fixed caller-chosen order vs. random order are
  contradictory intents; one per profile. Chrome-style: `true` + GREASE,
  no fixed order. Firefox-style: fixed order, `false`.
- **`grease_enabled`** — injects GREASE values (random unknown cipher /
  extension codepoints). Browsers do this to keep middleboxes honest;
  JA3/JA4 hashes normally normalize GREASE away, so it changes the wire
  bytes without changing the hash.
- **`status_request`** — OCSP stapling. Sent by real browsers by default.
- **`signed_certificate_timestamp`** — Certificate Transparency SCT
  extension. Also default-on in real browsers.
- **`session_ticket`** — whether the `session_ticket` extension is sent
  (`NO_TICKET` option cleared/set). Each upstream connection is fresh, so
  this only controls the extension's *presence* for fingerprinting — no
  real session resumption happens.
- **`alps`** — Application-Layer Protocol Settings. Sends an ALPS payload
  for `h2` encoded from the same `http2.settings` / `settings_order`
  used for the real HTTP/2 SETTINGS frame (see `HTTP2.md`) — browsers use
  that exact encoding, so no separate config exists. Empty `settings`
  means an empty ALPS payload.

### `delegated_credentials` — opt-in extension

List of signature-scheme names (same vocabulary as
`signature_algorithms`), enables the `delegated_credentials` extension.
`null` = extension absent.

### `record_size_limit` — int or `null`

Advertises the maximum TLS record size the client accepts
(`record_size_limit` extension). `null` = extension absent.

### `doh` — resolvers for ECH lookup

Hostnames of DoH resolvers (e.g. `["dns.google"]`), picked at random per
lookup. Used only when `enable_ech` is `true`. See below.

## Encrypted Client Hello (ECH)

Two **independent** booleans:

- **`enable_ech`** — resolve a real ECH config at all. When `true`, the
  proxy looks one up per upstream host and encrypts the inner ClientHello
  with it. When `false`, no lookup happens.
- **`enable_ech_grease`** — send ECH GREASE as fallback whenever no real
  config is used — both when `enable_ech` is `false` and when it is
  `true` but no config was found for that host. Real browsers send this
  on every handshake either way.

| `enable_ech` | `enable_ech_grease` | Behavior |
|---|---|---|
| `false` | `false` | No ECH extension at all. |
| `false` | `true` | Always GREASE, never look anything up. |
| `true` | `false` | Real ECH where published; nothing elsewhere. |
| `true` | `true` | Real ECH where published; GREASE elsewhere — matches real Chrome/Firefox on the open web. |

How the real config is resolved (only when `enable_ech` is `true`):

1. Pick a random resolver from `doh`, so repeat lookups spread across
   resolvers.
2. Query the target host's **HTTPS (SVCB) record** and read the `ech`
   parameter, if present.
3. **The DoH request goes through the proxy's own fingerprinting stack**
   — a full TLS + HTTP/2 connection built with the same profile. It
   never attempts ECH resolution for itself (that would recurse).
4. **With `upstream_proxy` set, DoH is routed through it too** — no
   direct-to-internet path exists, so ECH lookups can't leak the target
   host to local-network observers.
5. Result (config bytes or absence) is cached per domain for one hour
   (`moka`, up to 10,000 entries).

## JA3 / JA4 notes

- JA3 hashes the ordered cipher list, extensions list, curves and point
  formats — all four are profile-controlled here (point formats ride
  along with the BoringSSL defaults for the chosen curves).
- JA4 additionally folds in ALPN, SNI presence (`server_name` position in
  `extensions_order`), and counts — same story.
- GREASE codepoints are stripped by the hashers before hashing, so
  `grease_enabled` / `enable_ech_grease` affect middlebox behavior, not
  the hash.

## Per-domain TLS (`-d domain.json`)

Any `tls` field can be overridden per domain pattern; unspecified fields
inherit the base profile, `"field": null` resets a list to absent. Useful
for fingerprint-sensitive checkers (weaker cipher subset, no ECH) or for
hosts that break under a particular extension:

```json
{
    "browserleaks.com": {
        "config": { "upstream_proxy": null },
        "tls": {
            "cipher_suites": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "ECDHE-ECDSA-AES128-GCM-SHA256",
                "ECDHE-RSA-AES128-GCM-SHA256",
                "TLS_RSA_WITH_AES_256_CBC_SHA"
            ],
            "enable_ech": false
        }
    }
}
```

## Gotchas

- TLS 1.2 suites in `TLS_..._WITH_...` long form are rejected — use the
  short OpenSSL names. TLS 1.3 suites use the `TLS_...` IANA names.
  Mixing the conventions up is the most common config error.
- `extensions_order` must list **every** active extension, or positions
  are undefined. When in doubt, capture a real browser Hello
  (e.g. via `tls.peet.ws` or Wireshark) and mirror it.
- `permute_extensions: true` + populated `extensions_order` =
  contradictory config. Pick one.
- `cert_compression` with an unknown name fails the connection at build
  time — loud, not silent.
- ECH lookups cost one DoH round-trip per unseen host (then cached);
  `enable_ech: true` with an unreachable resolver stalls handshakes to
  its timeout.
