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

## TLS Boolean Toggles

A handful of extensions are controlled by a single `bool` in `TlsConfig`
rather than a list or an order — either the extension/behavior is present,
or it isn't:

- **`permute_extensions`** — randomizes the order of TLS extensions on
  every handshake, matching Chrome's behavior (`SSL_CTX_set_permute_extensions`
  under the hood). **Do not combine this with a populated `extensions_order`**
  — the two express contradictory intents (a fixed, caller-chosen order vs.
  a random one on every handshake) and only one should be set per profile.
  Chrome-style profiles use `permute_extensions: true` with GREASE and no
  fixed order; Firefox-style profiles use a fixed `extensions_order` and
  leave this `false`.
- **`status_request`** — enables OCSP stapling (the `status_request`
  extension). Real browsers send this by default.
- **`signed_certificate_timestamp`** — enables the Certificate Transparency
  SCT extension. Also on by default in real browsers.
- **`session_ticket`** — controls whether the `session_ticket` extension is
  sent at all (`SSL_OP_NO_TICKET` under the hood). Since each upstream
  connection is established fresh rather than reusing a cached session, this
  only affects whether the extension is *present* in the ClientHello for
  fingerprinting purposes — it does not enable real session resumption.
- **`alps`** — enables Application-Layer Protocol Settings (ALPS). When on,
  the proxy sends an ALPS payload for the `h2` protocol built from the same
  `settings` / `settings_order` fields used for the real HTTP/2 SETTINGS
  frame (see `HTTP2.md`) — real browsers use this exact same encoding for
  the ALPS payload, so no separate configuration is needed. If `settings`
  is empty, an empty ALPS payload is sent.

## A note on `renegotiation_info`

The `renegotiation_info` extension (RFC 5746, Secure Renegotiation
Indication) is not user-toggleable and doesn't need to be — BoringSSL always
sends it as a baseline security measure, the same way every modern browser
does. It only needs a position in `extensions_order`; there's nothing to
enable or disable.
