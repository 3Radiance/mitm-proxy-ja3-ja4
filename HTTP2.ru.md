## HTTP/2 Fingerprinting (Akamai)

HTTP/2-фингерпринтинг полностью настраивается через секцию `http2` JSON-профиля. Конфигурация управляет поведением connection preface, SETTINGS-фреймом, приоритетами потоков, порядком заголовков, расположением `END_STREAM` и изменением HTTP-заголовков.

Пример:

```json
"http2": {
    "settings": {
        "header_table_size": 65536,
        "enable_push": false,
        "max_concurrent_streams": null,
        "initial_window_size": 131072,
        "max_frame_size": 16384,
        "max_header_list_size": null
    },

    "settings_order": [
        "HEADER_TABLE_SIZE",
        "ENABLE_PUSH",
        "INITIAL_WINDOW_SIZE",
        "MAX_FRAME_SIZE"
    ],

    "connection_window_update": 12582912,

    "initial_stream_id": null,

    "priority_frames": null,

    "headers_priority": {
        "exclusive": false,
        "depends_on": 0,
        "weight": 41
    },

    "end_stream_on_headers": false,

    "pseudo_headers_order": [
        ":method",
        ":path",
        ":authority",
        ":scheme"
    ],

    "headers_order": [
        "user-agent",
        "accept-language"
    ],

    "http_headers": {
        "user-agent": "Mozilla/5.0",
        "accept-language": "en-US,en;q=0.6"
    }
}
```

### SETTINGS

Объект `settings` управляет значениями, которые отправляются в HTTP/2 `SETTINGS`-фрейме.

Поддерживаемые поля:

* `header_table_size` — размер динамической таблицы HPACK. Используйте `null`, чтобы не отправлять этот параметр.
* `enable_push` — включает или отключает HTTP/2 Server Push.
* `max_concurrent_streams` — максимальное количество одновременно активных потоков. Используйте `null`, чтобы не отправлять этот параметр.
* `initial_window_size` — начальный размер окна flow control для потоков.
* `max_frame_size` — максимальный размер payload HTTP/2-фрейма.
* `max_header_list_size` — максимальный размер списка заголовков. Используйте `null`, чтобы не отправлять этот параметр.

Значения отправляются в соответствии с `settings_order`.

### Порядок SETTINGS

`settings_order` управляет порядком отдельных параметров SETTINGS в исходящем SETTINGS-фрейме.

Поддерживаемые значения:

```text
HEADER_TABLE_SIZE

ENABLE_PUSH

MAX_CONCURRENT_STREAMS

INITIAL_WINDOW_SIZE

MAX_FRAME_SIZE

MAX_HEADER_LIST_SIZE
```

Отправляются только те настройки, которые присутствуют в конфигурации.

Например:

```json
"settings_order": [
    "HEADER_TABLE_SIZE",
    "ENABLE_PUSH",
    "INITIAL_WINDOW_SIZE",
    "MAX_FRAME_SIZE"
]
```

отправит настроенные параметры именно в указанном порядке.

### Обновление connection window

`connection_window_update` управляет величиной увеличения connection-level `WINDOW_UPDATE`, отправляемого после установки HTTP/2-соединения.

Например:

```json
"connection_window_update": 12582912
```

Этот параметр управляет окном flow control всего соединения независимо от `initial_window_size`, который применяется к отдельным потокам.

### Начальный ID потока

`initial_stream_id` определяет ID первого клиентского HTTP/2-потока.

Если `initial_stream_id` задан явно, используется указанное значение.

Если значение равно `null`, ID вычисляется автоматически:

* без priority-фреймов начальный stream ID равен `1`;
* при наличии priority-фреймов начальный stream ID вычисляется как максимальный настроенный priority stream ID плюс `2`.

Например, если настроены следующие priority-потоки:

```json
"priority_frames": [
    {
        "stream_id": 1,
        "exclusive": false,
        "depends_on": 0,
        "weight": 41
    },
    {
        "stream_id": 3,
        "exclusive": false,
        "depends_on": 0,
        "weight": 42
    }
]
```

начальный stream ID автоматически будет равен `5`.

Это важно, поскольку HTTP/2 priority-фреймы могут занимать stream ID ещё до создания первого реального request stream. Если priority-фреймы настроены, не следует вручную задавать `initial_stream_id`, конфликтующий с этими потоками.

При ручной настройке `initial_stream_id` вместе с `priority_frames` убедитесь, что выбран подходящий свободный client stream ID и соблюдаются правила HTTP/2 для stream ID.

### Priority-фреймы

`priority_frames` — это массив определений HTTP/2-приоритетов, которые отправляются до обычных request streams.

Каждый элемент содержит:

```json
{
    "stream_id": 1,
    "exclusive": false,
    "depends_on": 0,
    "weight": 41
}
```

Поля:

* `stream_id` — ID потока, связанный с определением приоритета. Для клиентских потоков используются нечётные stream ID.
* `exclusive` — определяет, становится ли зависимость исключительной.
* `depends_on` — ID родительского потока.
* `weight` — вес приоритета потока.

Пример:

```json
"priority_frames": [
    {
        "stream_id": 1,
        "exclusive": false,
        "depends_on": 0,
        "weight": 41
    },
    {
        "stream_id": 3,
        "exclusive": false,
        "depends_on": 0,
        "weight": 42
    }
]
```

Если priority-фреймы настроены, а `initial_stream_id` равен `null`, прокси автоматически выбирает следующий доступный нечётный stream ID после максимального настроенного priority stream.

### Приоритет заголовков

`headers_priority` управляет приоритетом, связанным с request HEADERS stream.

Пример:

```json
"headers_priority": {
    "exclusive": false,
    "depends_on": 0,
    "weight": 41
}
```

Поля имеют то же значение, что и у priority-фреймов:

* `exclusive`
* `depends_on`
* `weight`

Установите `headers_priority` в `null`, если специальный приоритет для заголовков не требуется.

### END_STREAM в request HEADERS

`end_stream_on_headers` управляет расположением `END_STREAM` для запросов, у которых отсутствует тело.

При значении `true`:

```text
HEADERS + END_STREAM
```

используется для пустого запроса.

При значении `false`:

```text
HEADERS
DATA(length=0) + END_STREAM
```

используется вместо этого.

Для запросов, содержащих тело, `END_STREAM` отправляется в последнем DATA-фрейме, и эта настройка не переносит его в начальный HEADERS-фрейм.

Это позволяет подбирать последовательность HTTP/2-фреймов под разные клиентские фингерпринты.

### Порядок pseudo-заголовков

`pseudo_headers_order` управляет порядком HTTP/2 pseudo-заголовков в исходящих запросах.

Поддерживаемые pseudo-заголовки:

```text
:method

:path

:authority

:scheme
```

Пример:

```json
"pseudo_headers_order": [
    ":method",
    ":path",
    ":authority",
    ":scheme"
]
```

Указанный порядок сохраняется при построении исходящего запроса.

### Порядок HTTP-заголовков

`headers_order` управляет порядком обычных HTTP-заголовков запроса.

Пример:

```json
"headers_order": [
    "user-agent",
    "accept-language",
    "accept-encoding",
    "referer"
]
```

Указанные здесь заголовки обрабатываются строго в этом порядке.

### Изменение HTTP-заголовков

`http_headers` управляет значениями отдельных HTTP-заголовков.

Строковое значение заменяет входящее значение:

```json
"http_headers": {
    "user-agent": "Mozilla/5.0"
}
```

Заголовок можно удалить, установив его значение в `null`:

```json
"http_headers": {
    "referer": null
}
```

Заголовки также можно добавить, даже если их не было в исходном запросе:

```json
"http_headers": {
    "priority": "u=0, i"
}
```

Заголовки, которые не указаны в `http_headers`, сохраняются из входящего запроса.

Таким образом, можно:

* заменять существующие заголовки;
* удалять заголовки;
* добавлять новые заголовки;
* сохранять неуказанные входящие заголовки;
* управлять итоговым порядком заголовков через `headers_order`.

Например:

```json
"headers_order": [
    "user-agent",
    "accept",
    "accept-language",
    "priority"
],

"http_headers": {
    "user-agent": "Mozilla/5.0",
    "accept-language": "en-US,en;q=0.6",
    "priority": "u=0, i",
    "referer": null
}
```

В этой конфигурации:

* `user-agent` заменяется;
* `accept-language` заменяется;
* `priority` добавляется;
* `referer` удаляется;
* `accept` сохраняется из входящего запроса;
* итоговые заголовки следуют настроенному порядку.

### Потоковая передача HTTP/2 request и response

Тела запросов и ответов передаются в потоковом режиме, без полного буферизования тела в памяти.

Прокси также сохраняет HTTP/2 trailing headers (trailers). Если присутствуют trailers, последний DATA-фрейм не содержит `END_STREAM`; вместо этого поток закрывается завершающим HEADERS-фреймом.

Без trailers:

```text
HEADERS

DATA

DATA + END_STREAM
```

С trailers:

```text
HEADERS

DATA

DATA

TRAILERS + END_STREAM
```
