## Поддерживаемые наборы шифров

BoringSSL хранит наборы шифров TLS 1.3 и TLS 1.2 как два раздельных
внутренних списка — их нельзя перемешать в конфиге, BoringSSL всегда
сгруппирует их в два непрерывных блока (сначала TLS 1.3, потом TLS 1.2),
независимо от порядка, в котором они указаны в `cipher_suites`. Так же
строится ClientHello и у настоящих браузеров, так что это не ограничение,
которое нужно как-то обходить.

Названия у них тоже разные: наборы TLS 1.3 используют IANA-имена вида
`TLS_<AEAD>_<HASH>`, а наборы TLS 1.2 нужно передавать в коротких именах
OpenSSL-стиля (`ECDHE-ECDSA-AES128-GCM-SHA256`) — длинная форма
`TLS_ECDHE_..._WITH_...` для TLS 1.2 **не принимается**.

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

## Поддерживаемые кривые

Полный список (BoringSSL):
```
P-256
P-384
P-521
X25519
X25519Kyber768Draft00
X25519MLKEM768
MLKEM1024
```

## Поддерживаемые алгоритмы подписи

Полный список (BoringSSL):
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

## Поддерживаемые алгоритмы сжатия сертификата

Поле `cert_compression` принимает список названий алгоритмов. За каждым
стоит реальный декомпрессор (а не заглушка), поэтому хендшейк корректно
завершится, даже если сервер реально пришлёт сертификат, сжатый одним из
них:
```
brotli
zlib
zstd
```

## Поддерживаемые значения для порядка расширений

Поле `extensions_order` управляет позицией каждого TLS-расширения в
исходящем ClientHello (под капотом — `SSL_CTX_set_extension_order`). Сюда
нужно включить **все** расширения, которые реально активны в хендшейке —
включённые через `cipher_suites`, `curves`, `signature_algorithms`, `alpn`,
`cert_compression`, `record_size_limit` и т.д. **Если активное расширение
не указано в `extensions_order`, его итоговая позиция не определена** —
нет гарантии, что оно будет отброшено, добавлено в конец или поставлено в
каком-то конкретном месте, такое поведение нигде не задокументировано выше
по стеку. Всегда указывай каждое включённое расширение.

Полный список поддерживаемых имён:
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
