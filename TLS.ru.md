# Подмена TLS-отпечатка (JA3/JA4)

[English](TLS.md) | [Русский](TLS.ru.md)

Апстрим TLS-соединение целиком строится из JSON-профиля: каждый байт
ClientHello, который видит фингерпринт — порядок шифров, расширения и их
порядок, кривые, алгоритмы подписи, ALPN, GREASE, компрессия, ECH —
задаётся пользователем. Стек — BoringSSL через `btls` / `tokio-btls`
(`src/tls_fingerprint/`).

## Схема соединения

```
браузер ──ClientHello──▶ прокси
                            1. парсим CONNECT, достаём SNI/host
                            2. выбираем профиль по SNI (база или доменный оверлей)
                            3. открываем апстрим TCP (маркированный сокет, см. TCP.ru.md)
                            4. TLS-хендшейк СНАЧАЛА с апстримом, по профилю
                            5. забираем апстримный ALPN, строим клиентский акцептор
браузер ◀──ServerHello (поддельный серт, апстримный ALPN)── прокси
```

Upstream-first важен: ALPN, выбранный настоящим сервером, определяет,
какой клиентский хендшейк получит браузер, — браузер никогда не
выберет протокол, который апстрим-соединение не говорит. Клиентская
сторона — акцептор `mozilla_intermediate` с сертификатом на лету
(`rcgen`, подпись локальным CA, кэш в `moka`) и ALPN-колбэком,
повторяющим выбор апстрима (по умолчанию `http/1.1`).

Апстрим `SslConnector` собирается в `create_ssl_acceptor_upstream`
(`src/tls_fingerprint/tls.rs`) в таком порядке: наборы шифров → ALPN →
кривые → алгоритмы подписи → record size limit → компрессия сертификата
→ GREASE → перестановка/порядок расширений → OCSP → SCT → session
ticket → delegated credentials → порядок расширений → ALPS → ECH.
Проверка серта — по Chromium root store. Таймаут хендшейка — 5 секунд.

## Конфигурация (блок `tls`)

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

### `cipher_suites` — строгий порядок, два блока

Список склеивается через `:` и уходит в `set_cipher_list`, а флаг
`set_preserve_tls13_cipher_list(true)` сохраняет твой порядок как есть.
BoringSSL хранит наборы TLS 1.3 и TLS 1.2 двумя раздельными внутренними
списками — перемешать их нельзя, BoringSSL всегда испустит два цельных
блока (сначала TLS 1.3, потом TLS 1.2), как бы они ни были перемешаны в
конфиге. Настоящие браузеры строят ClientHello так же, так что это не
ограничение, которое надо обходить.

Имена разные для версий: наборы TLS 1.3 — IANA-имена вида
`TLS_<AEAD>_<HASH>`, наборы TLS 1.2 — короткие имена OpenSSL-стиля
(`ECDHE-ECDSA-AES128-GCM-SHA256`); длинная форма `TLS_ECDHE_..._WITH_...`
для TLS 1.2 **не принимается**.

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

### `alpn` — список протоколов

Склеивается в wire-формат с длинами (`encode_alpn_wire`) и предлагается
серверу. Выбор сервера определяет, на чём в итоге говорит всё соединение —
и клиентский хендшейк тоже.

### `curves` — группы, по порядку

Уходит в `set_curves_list`. Полный словарь BoringSSL:
```
P-256
P-384
P-521
X25519
X25519Kyber768Draft00
X25519MLKEM768
MLKEM1024
```

### `signature_algorithms` — по порядку

Уходит в `set_sigalgs_list`. Полный словарь:
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

### `extensions_order` — точные позиции расширений

Управляет позицией каждого TLS-расширения в исходящем ClientHello
(под капотом — `set_extension_permutation`). Сюда нужно включить **все**
расширения, реально активные в хендшейке — включённые через
`cipher_suites`, `curves`, `signature_algorithms`, `alpn`,
`cert_compression`, `record_size_limit` и т.д. **Если активное расширение
не указано, его итоговая позиция не определена** — нет гарантии, что оно
будет отброшено, добавлено в конец или встанет куда-то конкретно, выше по
стеку такое поведение нигде не задокументировано. Всегда перечисляй всё
включённое.

Поддерживаемые имена (у части есть алиасы):

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

`renegotiation_info` (RFC 5746) не тогглится и тоггла не требует —
BoringSSL шлёт его всегда, как любой современный браузер; ему нужна
только позиция в этом списке.

### `cert_compression` — с рабочими декомпрессорами

За каждым именем стоит реальный декомпрессор, так что хендшейк корректно
завершится, даже если сервер реально пришлёт сжатый одним из них серт:

```
brotli
zlib
zstd
```

Неизвестное имя — жёсткая ошибка, а не молчаливый скип.

### Булевы переключатели

- **`permute_extensions`** — рандомизирует порядок расширений на каждом
  хендшейке (поведение Chrome). **Никогда не сочетай с заполненным
  `extensions_order`** — фиксированный заданный порядок против случайного
  на каждом хендшейке, в одном профиле только одно из двух.
  Chrome-стиль: `true` + GREASE, без фиксированного порядка.
  Firefox-стиль: фиксированный порядок, `false`.
- **`grease_enabled`** — вставляет GREASE-значения (случайные неизвестные
  шифр/кодпоинт расширения). Браузеры делают так, чтобы мидлбоксы были
  честными; хэшеры JA3/JA4 GREASE обычно нормализуют прочь, так что байты
  на проводе меняются, а хэш — нет.
- **`status_request`** — OCSP stapling. Настоящие браузеры шлют по
  умолчанию.
- **`signed_certificate_timestamp`** — SCT-расширение Certificate
  Transparency. У настоящих браузеров тоже default-on.
- **`session_ticket`** — отправлять ли расширение `session_ticket`
  вообще (снимает/ставит опцию `NO_TICKET`). Каждое апстрим-соединение
  свежее, так что это влияет только на *присутствие* расширения ради
  отпечатка — реального возобновления сессии не происходит.
- **`alps`** — Application-Layer Protocol Settings. Отправляет ALPS-пейлоад
  для `h2`, закодированный из тех же `http2.settings` / `settings_order`,
  что настоящий HTTP/2 SETTINGS-фрейм (см. `HTTP2.ru.md`), — браузеры
  используют ровно ту же кодировку, отдельной настройки нет. Пустой
  `settings` — пустой ALPS-пейлоад.

**### `delegated_credentials` — расширение, подключаемое по желанию**

Включает расширение TLS `delegated_credentials`.
Delegated Credentials (делегированные учётные данные) позволяют конечной точке TLS использовать краткоживущий делегированный ключ для TLS-рукопожатий вместо закрытого ключа, связанного с сертификатом.
Значением является список названий схем подписи, определяющих, какие алгоритмы могут использоваться для делегированных учётных данных.
`null` = расширение отсутствует.

Поддерживаемые значения:

```text
ecdsa_secp256r1_sha256
ecdsa_secp384r1_sha384
ecdsa_secp521r1_sha512
ed25519
ecdsa_sha1
```


### `record_size_limit` — число или `null`

Рекламирует максимальный принимаемый размер TLS-записи (расширение
`record_size_limit`). `null` = расширения нет.

### `doh` — резолверы для ECH-поиска

Имена хостов DoH-резолверов (напр. `["dns.google"]`), на каждый поиск
выбирается случайный. Используется только при `enable_ech: true`. См. ниже.

## Encrypted Client Hello (ECH)

Два **независимых** булевых поля:

- **`enable_ech`** — вообще искать реальный ECH-конфиг. При `true` прокси
  ищет его под каждый апстрим-хост и шифрует им внутренний ClientHello.
  При `false` поиска нет вообще.
- **`enable_ech_grease`** — слать ECH GREASE как фолбэк везде, где
  реальный конфиг не используется: и когда `enable_ech` равен `false`, и
  когда он `true`, но конфиг под конкретный хост не нашёлся. Настоящие
  браузеры шлют это расширение при каждом хендшейке так или иначе.

| `enable_ech` | `enable_ech_grease` | Поведение |
|---|---|---|
| `false` | `false` | ECH-расширения нет вообще. |
| `false` | `true` | Всегда GREASE, ничего никогда не ищется. |
| `true` | `false` | Реальный ECH где опубликован; больше ничего. |
| `true` | `true` | Реальный ECH где опубликован; GREASE в остальных — как настоящие Chrome/Firefox в открытом интернете. |

Как разрешается реальный конфиг (только при `enable_ech: true`):

1. Случайный резолвер из `doh`, чтобы повторные поиски размазывались.
2. У цели запрашивается **HTTPS (SVCB) запись**, из неё забирается
   параметр `ech`, если есть.
3. **Сам DoH-запрос идёт через собственный фингерпринт-стек прокси** —
   полноценное TLS + HTTP/2-соединение по тому же профилю. ECH для
   самого себя он никогда не ищет (это рекурсия).
4. **При заданном `upstream_proxy` DoH идёт через него же** — прямого
   пути в интернет нет, так что поиск ECH-конфига не утечёт и не выдаст
   целевой хост наблюдателям локальной сети.
5. Результат (байты конфига или его отсутствие) кэшируется по домену на
   час (`moka`, до 10 000 записей).

## Заметки про JA3 / JA4

- JA3 хэширует упорядоченный список шифров, список расширений, кривые и
  point formats — все четыре тут управляются профилем (point formats
  едут вместе с дефолтами BoringSSL под выбранные кривые).
- JA4 сверху сворачивает ALPN, присутствие SNI (позиция `server_name` в
  `extensions_order`) и счётчики — та же история.
- GREASE-кодпоинты хэшеры вырезают до хэширования, так что
  `grease_enabled` / `enable_ech_grease` влияют на поведение мидлбоксов,
  а не на хэш.

## TLS по доменам (`-d domain.json`)

Любое поле `tls` переопределяется под паттерн домена; неуказанные поля
наследуются из базы, `"поле": null` сбрасывает список в отсутствие.
Удобно для чекеров отпечатков (урезанный набор шифров, без ECH) или
хостов, ломающихся от конкретного расширения:

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

## Грабли

- Наборы TLS 1.2 в длинной форме `TLS_..._WITH_...` отвергаются — только
  короткие имена OpenSSL. Наборы TLS 1.3 — имена `TLS_...` IANA.
  Перепутать конвенции — самая частая ошибка конфига.
- В `extensions_order` должно быть **каждое** активное расширение, иначе
  позиции не определены. Если сомневаешься — сними настоящий Hello
  браузера (напр. через `tls.peet.ws` или Wireshark) и отзеркаль.
- `permute_extensions: true` + заполненный `extensions_order` =
  противоречивый конфиг. Выбери одно.
- `cert_compression` с неизвестным именем роняет соединение на этапе
  сборки — громко, а не тихо.
- ECH-поиск стоит один DoH round-trip на невиданный хост (дальше кэш);
  `enable_ech: true` с недостижимым резолвером подвесит хендшейки на его
  таймаут.
