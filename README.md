# mitm-proxy-ja3-ja4

HTTP MITM-прокси с подменой TLS/HTTP-2 отпечатков (JA3/JA4 + Akamai) и кастомным User-Agent. Построен на Rust + [hudsucker](https://github.com/omjadas/hudsucker).

> ⚠️ **Без Firefox Multi-Account Containers прикол пропадает.** Контейнеры позволяют одновременно использовать разные JA3/JA4-отпечатки в разных вкладках. Без них весь браузер ходит через один прокси с одним фингерпринтом — это палево и бесполезно для мультиаккаунтинга.

## Архитектура

```
Firefox Container A (VPN)  → MITM Proxy :8001 → v2rayN/SOCKS5 :10808 → VPN → Интернет
Firefox Container B (Рунет) → Интернет
```

Прокси перехватывает HTTPS-трафик, динамически генерирует сертификаты для каждого домена (через собственный CA), модифицирует HTTP-заголовки и проксирует соединения через upstream SOCKS5.

## Возможности

- 🔒 **MITM (Man-in-the-Middle)** — прозрачная расшифровка HTTPS с динамической генерацией сертификатов
- 🎭 **JA3/JA4 Spoofing** — кастомный набор TLS cipher suites для изменения TLS-отпечатка
- 🌐 **Akamai HTTP/2 Fingerprint** — настройка window sizes и параметров HTTP/2
- 🧦 **Upstream SOCKS5** — проксирование через v2rayN, Shadowsocks и т.д.
- 📝 **User-Agent Spoofing** — подмена заголовка `User-Agent` на уровне прокси
- ⚙️ **Systemd Service** — готовая интеграция с NixOS

## Требования

- Rust (edition 2021)
- NixOS (для systemd-интеграции) или любой Linux
- Firefox + [Multi-Account Containers](https://addons.mozilla.org/firefox/addon/multi-account-containers/)
- [Container Proxy](https://addons.mozilla.org/firefox/addon/container-proxy/) (или аналог) для привязки прокси к контейнерам
- v2rayN / любой SOCKS5-прокси

## Установка

### 1. Клонирование и сборка

```bash
git clone https://github.com/3Radiance/mitm-proxy-ja3-ja4.git
cd mitm-proxy-ja3-ja4
cargo build --release
```

### 2. Запуск

```bash
cargo run
# или
./target/release/mitm-proxy-ja3-ja4
```

При первом запуске сгенерируются файлы:
- `ca-cert.pem` — корневой сертификат (нужно импортировать в Firefox)
- `ca-key.pem` — приватный ключ CA

## Настройка Firefox

### 1. Установи расширения

- [Firefox Multi-Account Containers](https://addons.mozilla.org/firefox/addon/multi-account-containers/)
- [Container Proxy](https://addons.mozilla.org/firefox/addon/container-proxy/)

### 2. Создай контейнеры

- **VPN** — для трафика через VPN/зарубежный SOCKS5
- **Рунет** — для трафика через российский айпи

### 3. Назначь прокси через Container Proxy

- Контейнер **VPN** → `127.0.0.1:8001`
- Контейнер **Рунет** → `Directly`


### 4. Импортируй CA

- Открой `about:preferences#privacy` → **Сертификаты** → **Просмотр сертификатов...**
- Вкладка **Центры сертификации** → **Импортировать...**
- Выбери `ca-cert.pem`
- ☑ Доверять при идентификации веб-сайтов
- ☑ Доверять при идентификации разработчиков ПО
- **Перезапусти Firefox**

## Почему именно контейнеры?

Без контейнеров весь Firefox ходит через один прокси — и у тебя **один JA3/JA4 на все вкладки**. Это палево:
- Ты зашёл в аккаунт А с отпечатком X
- Ты зашёл в аккаунт Б с тем же отпечатком X
- Сайт связывает аккаунты по fingerprint

**С контейнерами:**
- Аккаунт А в контейнере VPN → JA3 `24924417...`, IP из Нидерландов
- Аккаунт Б в контейнере Рунет → JA3 `868929d9...`, IP из Москвы


Каждый контейнер — изолированная среда с **своими** cookies, localStorage, прокси и fingerprint'ом.

## Настройка NixOS (Systemd)

Добавь в `configuration.nix`:

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

После `sudo nixos-rebuild switch`:

```bash
# Если переносишь существующие сертификаты:
sudo cp ~/mitm-proxy-ja3-ja4/ca-cert.pem /var/lib/socks5-mitm/
sudo cp ~/mitm-proxy-ja3-ja4/ca-key.pem /var/lib/socks5-mitm/
sudo chown socks5-mitm:socks5-mitm /var/lib/socks5-mitm/ca-cert.pem
sudo chown socks5-mitm:socks5-mitm /var/lib/socks5-mitm/ca-key.pem
sudo chmod 600 /var/lib/socks5-mitm/ca-key.pem

sudo systemctl restart socks5-mitm
sudo systemctl status socks5-mitm
```

## Кастомизация

### User-Agent

В `src/main.rs`, в `handle_request`:

```rust
req.headers_mut().insert(
    "user-agent",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
        .parse()
        .unwrap(),
);
```

### TLS Cipher Suites (JA3/JA4)

В `build_custom_ja3_tls_config()`:

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

В `main()`:

```rust
client_builder.http2_initial_stream_window_size(65535);
client_builder.http2_initial_connection_window_size(15663105);
```

### Upstream SOCKS5

```rust
const SOCKS5_UPSTREAM: &str = "127.0.0.1:10808";
```

## Проверка

Зайди на [browserleaks.com](https://browserleaks.com) и сравни отпечатки:

| | Без прокси | Контейнер VPN | Контейнер Рунет |
|---|---|---|---|
| **JA3** | `868929d9...` | `24924417...` | `24924417...` или свой |
| **JA4** | `t13d1517h2...` | `t13d0612h2...` | `t13d0612h2...` или свой |
| **Akamai** | `6ea73faa...` | `39eaae6c...` | `39eaae6c...` или свой |

## Лицензия

MIT
