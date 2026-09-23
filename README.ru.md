# mitm-proxy-ja3-ja4

[English](README.md) | [Русский](README.ru.md)

HTTP MITM-прокси на Rust, `tokio` и `btls`.

> **Сейчас на стадии MVP (Minimum Viable Product).**

Проект полностью переписан на `btls` (BoringSSL) для продвинутого TLS-фингерпринтинга. На данный момент это прозрачный MITM-прокси с поддержкой апстрим-прокси, но подмена TLS-отпечатка пока частичная.

## Возможности (текущая реализация)

- **MITM (Man-in-the-Middle)** — прозрачный перехват HTTPS. Сертификаты выпускаются и подписываются на лету через `rcgen`, кэшируются в `dashmap` для производительности.
- **Интеграция BoringSSL** — TLS-хендшейк и MITM-перехват реализованы через `btls` и `tokio-btls`.
- **Подмена TLS-отпечатка** — апстрим-соединение выставляет наборы шифров, эллиптические кривые и алгоритмы подписи в строгом порядке, заданном пользователем, загружая их из JSON-конфига через `-c` / `--config <путь>` (формат см. в `example.json` в репозитории). Полные списки поддерживаемого — ниже: [шифры](#поддерживаемые-наборы-шифров), [кривые](#поддерживаемые-кривые), [алгоритмы подписи](#поддерживаемые-алгоритмы-подписи), [расширения](#поддерживаемые-расширения).
- **Поддержка апстрим HTTP-прокси** — соединения можно проксировать через апстрим HTTP-прокси методом `CONNECT` (настраивается через CLI).
- **Асинхронность** — построено на `tokio` для высокопроизводительного неблокирующего ввода-вывода.

## Планы на будущее

Текущая архитектура — основа для полноценной подмены отпечатков:

- **Динамический спуфинг отпечатков (JSON-профили)**
  Расширить существующий JSON-профиль (`-c` / `--config`) на порядок TLS-расширений, ALPN, HTTP/2 (Akamai) и TCP-параметры — сейчас он управляет наборами шифров, кривыми и алгоритмами подписи.
- **L4 TCP-фингерпринтинг (NFQueue)**
  Реализовать модуль уровня L4 на Linux `nfqueue` (Netfilter Queue) для подмены TCP-отпечатка: TTL, размер TCP-окна, MSS, window scaling и точный порядок TCP-опций.

## Требования

- Rust (edition 2021)
- Linux (для будущих L4-функций на `nfqueue`)
- Firefox с расширением [Multi-Account Containers](https://addons.mozilla.org/firefox/addon/multi-account-containers/) (настоятельно рекомендуется для одновременного использования нескольких отпечатков)

## Установка и запуск

### 1. Сборка
```bash
git clone https://github.com/3Radiance/mitm-proxy-ja3-ja4.git
cd mitm-proxy-ja3-ja4
cargo build --release
```

### 2. Запуск

Все настройки — порт, апстрим-прокси и пути к файлам CA — теперь задаются в JSON-конфиге, который передаётся через `-c` / `--config <путь>`. Флагов `--port` / `--upstream` больше нет.

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

Чтобы запустить без апстрим-прокси, укажи `"upstream_proxy": null`.

```bash
cargo run --release -- --config profile.json
# или
cargo run --release -- -c profile.json
```

При первом запуске, если файлы `cert`/`key` ещё не существуют, прокси сгенерирует CA по указанным путям:
- `ca.crt` — корневой сертификат CA. Его нужно импортировать в Firefox/браузер и добавить в доверенные, чтобы сайты определялись корректно.
- `ca.key` — приватный ключ CA.

## Архитектура

- `src/main.rs`: точка входа CLI, единственный флаг `-c` / `--config <путь>` — порт, апстрим-прокси и пути к CA теперь задаются внутри JSON-конфига.
- `src/proxy/tcp.rs`: обработка TCP-соединений, разбор начального HTTP `CONNECT`, установка апстрим-соединения и связывание сырых сокетов с TLS MITM-слоем.
- `src/tls/cert.rs`: генерация сертификатов на лету через `rcgen` и `btls::x509`, подпись локальным CA, кэширование в `DashMap`.
- `src/tls/tls.rs`: настройка акцептора `btls` и обработка хендшейка (`tokio-btls`).

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

## Поддерживаемые значения для порядка расширений

Поле `extensions_order` управляет позицией каждого TLS-расширения в
исходящем ClientHello (под капотом — `SSL_CTX_set_extension_order`). Сюда
нужно включить **все** расширения, которые реально активны в хендшейке —
включённые через `cipher_suites`, `curves`, `signature_algorithms`, `alpn`
и т.д. **Если активное расширение не указано в `extensions_order`, его
итоговая позиция не определена** — нет гарантии, что оно будет отброшено,
добавлено в конец или поставлено в каком-то конкретном месте, такое
поведение нигде не задокументировано выше по стеку. Всегда указывай каждое
включённое расширение.

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


## Лицензия

MIT