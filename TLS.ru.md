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

## Булевы переключатели TLS

Несколько расширений управляются одним `bool` в `TlsConfig`, а не списком
или порядком — расширение/поведение либо есть, либо нет:

- **`permute_extensions`** — рандомизирует порядок TLS-расширений на
  каждом хендшейке, повторяя поведение Chrome (под капотом —
  `SSL_CTX_set_permute_extensions`). **Не сочетай это с заполненным
  `extensions_order`** — эти два поля выражают противоречащие друг другу
  намерения (фиксированный, заданный пользователем порядок против
  случайного на каждом хендшейке), и в одном профиле должно быть заполнено
  только одно из двух. Chrome-стиль использует `permute_extensions: true`
  вместе с GREASE и без фиксированного порядка; Firefox-стиль использует
  фиксированный `extensions_order` и оставляет это поле `false`.
- **`status_request`** — включает OCSP stapling (расширение
  `status_request`). Настоящие браузеры отправляют его по умолчанию.
- **`signed_certificate_timestamp`** — включает SCT-расширение
  (Certificate Transparency). Тоже включено по умолчанию у настоящих
  браузеров.
- **`session_ticket`** — управляет тем, отправляется ли расширение
  `session_ticket` вообще (под капотом — `SSL_OP_NO_TICKET`). Так как
  каждое апстрим-соединение устанавливается заново, а не переиспользует
  закэшированную сессию, это влияет только на *присутствие* расширения в
  ClientHello в целях фингерпринта — реальное возобновление сессии оно не
  включает.
- **`alps`** — включает Application-Layer Protocol Settings (ALPS). Когда
  включено, прокси отправляет ALPS-пейлоад для протокола `h2`, собранный
  из тех же полей `settings` / `settings_order`, что используются для
  настоящего HTTP/2 SETTINGS-фрейма (см. `HTTP2.ru.md`) — настоящие браузеры
  используют ту же самую кодировку для ALPS-пейлоада, так что отдельная
  настройка не нужна. Если `settings` пуст, отправляется пустой
  ALPS-пейлоад.

## Заметка про `renegotiation_info`

Расширение `renegotiation_info` (RFC 5746, Secure Renegotiation Indication)
не настраивается пользователем, и в этом нет необходимости — BoringSSL
всегда отправляет его как базовую меру безопасности, точно так же, как и
любой современный браузер. Ему нужна только позиция в `extensions_order`;
включать или выключать тут нечего.

## Encrypted Client Hello (ECH)

ECH управляется двумя **независимыми** булевыми полями в `TlsConfig`:

- **`enable_ech`** — включает разрешение ECH вообще. Когда `true`, прокси
  ищёт реальный ECH-конфиг для апстрим-хоста и, если находит, шифрует им
  внутренний ClientHello (под капотом — `SSL_set1_ech_config_list`). Когда
  `false`, поиск вообще не происходит — прокси сразу переходит к проверке
  `enable_ech_grease` ниже.
- **`enable_ech_grease`** — управляет тем, отправляется ли ECH GREASE как
  фолбэк в ситуациях, когда реальный конфиг не используется. Это касается
  **двух** случаев: когда `enable_ech` равен `false` (поиск вообще не
  предпринимался), и когда `enable_ech` равен `true`, но для конкретного
  хоста конфиг не нашёлся. В обоих случаях, если `enable_ech_grease` равен
  `true`, прокси отправляет GREASE ECH-расширение
  (`SSL_set_enable_ech_grease`) вместо этого — так же, как настоящие
  браузеры, которые отправляют это расширение при каждом хендшейке,
  независимо от того, поддерживает ли адресат ECH на самом деле.

Отсюда получается четыре реальных комбинации, соответствующих разному
поведению браузеров:

| `enable_ech` | `enable_ech_grease` | Поведение |
|---|---|---|
| `false` | `false` | ECH-расширения нет вообще. |
| `false` | `true` | Всегда GREASE — реальный конфиг никогда не ищется. |
| `true` | `false` | Реальный ECH, если конфиг есть; ничего, если его нет. |
| `true` | `true` | Реальный ECH, если конфиг есть; GREASE, если его нет — соответствует поведению настоящих Chrome/Firefox в открытом интернете, где большинство хостов пока не публикуют конфиг. |

### Как разрешается реальный конфиг

Когда `enable_ech` равен `true`, конфиг ищется вживую через DoH:

1. Выбирается случайный резолвер из списка `doh` (список имён хостов,
   например `["dns.google"]`), чтобы повторные запросы не шли все на один
   и тот же резолвер.
2. У него запрашивается **HTTPS (SVCB) запись** для целевого хоста, и из
   ответа, если он там есть, извлекается параметр `ech`
   (`SvcParamKey::EchConfigList`).
3. **Сам DoH-запрос идёт через собственный фингерпринт-стек прокси** — это
   полноценное TLS + HTTP/2-соединение, построенное через
   `create_ssl_acceptor_upstream`, с тем же профилем `TlsConfig` /
   `Http2Config`, что и обычный трафик. Оно **не** пытается разрешить ECH
   для самого себя (это привело бы к рекурсии), но во всём остальном
   выглядит как любое другое апстрим-соединение прокси.
4. **Если задан `upstream_proxy`, DoH-запрос тоже маршрутизируется через
   него** — отдельного прямого пути в интернет для DNS-резолвинга нет, так
   что поиск ECH-конфига не может утечь и выдать целевой хост никому, кто
   наблюдает за сетевым трафиком машины помимо настроенного прокси.
5. Результат (байты конфига, либо факт, что конфиг не найден) кэшируется
   по домену на один час (`moka`, до 10 000 записей), так что повторные
   визиты на один и тот же хост не опрашивают DoH заново каждый раз.