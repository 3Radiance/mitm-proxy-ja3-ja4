# mitm-proxy-ja3-ja4

[English](README.md) | [Русский](README.ru.md)

HTTP MITM-прокси на Rust, `tokio` и `btls`.

> **Сейчас на стадии MVP (Minimum Viable Product).**

Проект полностью переписан на `btls` (BoringSSL) для продвинутого TLS-фингерпринтинга. На данный момент это прозрачный MITM-прокси с поддержкой апстрим-прокси, но подмена TLS-отпечатка пока статичная и неконтролируемая.

## Возможности (текущая реализация)

- **MITM (Man-in-the-Middle)** — прозрачный перехват HTTPS. Сертификаты выпускаются и подписываются на лету через `rcgen`, кэшируются в `dashmap` для производительности.
- **Интеграция BoringSSL** — TLS-хендшейк и MITM-перехват реализованы через `btls` и `tokio-btls`.
- **Подмена набора шифров (Cipher Suite Spoofing)** — единственное, что реально работает прямо сейчас. Апстрим-соединение выставляет список TLS-шифров в строгом порядке, заданном пользователем, загружая его из JSON-конфига через `-c` / `--config <путь>` (формат см. в `example.json` в репозитории). Полный список поддерживаемых шифров — [ниже](#поддерживаемые-наборы-шифров).
- **Поддержка апстрим HTTP-прокси** — соединения можно проксировать через апстрим HTTP-прокси методом `CONNECT` (настраивается через CLI).
- **Асинхронность** — построено на `tokio` для высокопроизводительного неблокирующего ввода-вывода.

## Планы на будущее

Текущая архитектура — основа для полноценной подмены отпечатков:

- **Динамический спуфинг отпечатков (JSON-профили)**
  Расширить существующий JSON-профиль (`-c` / `--config`) на порядок TLS-расширений, HTTP/2 (Akamai) и TCP-параметры — сейчас он управляет только списком шифров.
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

Можно указать порт и опционально апстрим HTTP-прокси.

```bash
# Запуск на порту по умолчанию (9090)
cargo run --release

# Запуск на другом порту
cargo run --release -- --port 8080

# Запуск с апстрим HTTP-прокси
cargo run --release -- --upstream 127.0.0.1:10808

# Запуск с JSON-профилем отпечатка (пока управляет только порядком шифров)
cargo run --release -- --config profile.json
# или
cargo run --release -- -c profile.json
```

При первом запуске прокси сгенерирует в текущей директории файлы CA:
- `ca.crt` — корневой сертификат CA. Его нужно импортировать в Firefox/браузер и добавить в доверенные, чтобы сайты определялись корректно.
- `ca.key` — приватный ключ CA.

## Архитектура

- `src/main.rs`: точка входа CLI, разбор аргументов `--port`, `--upstream` и `-c` / `--config` (JSON-профиль отпечатка) через `clap`.
- `src/proxy/tcp.rs`: обработка TCP-соединений, разбор начального HTTP `CONNECT`, установка апстрим-соединения и связывание сырых сокетов с TLS MITM-слоем.
- `src/tls/cert.rs`: генерация сертификатов на лету через `rcgen` и `btls::x509`, подпись локальным CA, кэширование в `DashMap`.
- `src/tls/tls.rs`: настройка акцептора `btls` и обработка хендшейка (`tokio-btls`).

## Поддерживаемые наборы шифров

Полный список (BoringSSL):
```
TLS_AES_128_GCM_SHA256
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_256_GCM_SHA384
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_3DES_EDE_CBC_SHA
TLS_PSK_WITH_AES_128_CBC_SHA
TLS_PSK_WITH_AES_256_CBC_SHA
TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
```

## Поддерживаемые эллиптические кривые

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

## Лицензия

MIT