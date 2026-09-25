## HTTP/2 Fingerprinting (Akamai)

HTTP/2 fingerprinting is fully configurable through the `http2` section of the JSON profile. The configuration controls the connection preface behavior, SETTINGS frame, stream priorities, header ordering, `END_STREAM` placement, and HTTP header manipulation.

Example:

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

The `settings` object controls the values advertised in the HTTP/2 `SETTINGS` frame.

Supported fields:

* `header_table_size` — HPACK dynamic table size. Use `null` to omit the setting.
* `enable_push` — enables or disables HTTP/2 server push.
* `max_concurrent_streams` — maximum number of concurrently active streams. Use `null` to omit the setting.
* `initial_window_size` — initial flow-control window size for streams.
* `max_frame_size` — maximum HTTP/2 frame payload size.
* `max_header_list_size` — maximum header list size. Use `null` to omit the setting.

The values are sent according to `settings_order`.

### SETTINGS order

`settings_order` controls the order of individual SETTINGS parameters in the outgoing SETTINGS frame.

Supported values:

```text
HEADER_TABLE_SIZE
ENABLE_PUSH
MAX_CONCURRENT_STREAMS
INITIAL_WINDOW_SIZE
MAX_FRAME_SIZE
MAX_HEADER_LIST_SIZE
```

Only settings present in the configuration are emitted.

For example:

```json
"settings_order": [
    "HEADER_TABLE_SIZE",
    "ENABLE_PUSH",
    "INITIAL_WINDOW_SIZE",
    "MAX_FRAME_SIZE"
]
```

produces the configured settings in exactly that order.

### Connection window update

`connection_window_update` controls the connection-level `WINDOW_UPDATE` increment sent after the HTTP/2 connection is established.

For example:

```json
"connection_window_update": 12582912
```

This controls the connection flow-control window independently from the per-stream `initial_window_size`.

### Initial stream ID

`initial_stream_id` controls the first client-initiated HTTP/2 stream ID.

If `initial_stream_id` is set explicitly, that value is used.

If it is `null`, the value is calculated automatically:

* without priority frames, the initial stream ID is `1`;
* with priority frames, the initial stream ID is calculated as the highest configured priority stream ID plus `2`.

For example, if the configured priority streams are:

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

the initial stream ID is automatically calculated as `5`.

This is important because HTTP/2 priority frames can occupy stream IDs before the first actual request stream. When priority frames are configured, do not manually set an initial stream ID that conflicts with those streams.

When setting `initial_stream_id` manually together with `priority_frames`, make sure that it is an appropriate unused client stream ID and follows the HTTP/2 stream ID rules.

### Priority frames

`priority_frames` is an array of HTTP/2 priority definitions that are sent before normal request streams.

Each entry contains:

```json
{
    "stream_id": 1,
    "exclusive": false,
    "depends_on": 0,
    "weight": 41
}
```

Fields:

* `stream_id` — stream ID associated with the priority definition. Client-initiated streams use odd stream IDs.
* `exclusive` — whether the dependency becomes exclusive.
* `depends_on` — parent stream ID.
* `weight` — stream priority weight.

Example:

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

When priority frames are configured and `initial_stream_id` is `null`, the proxy automatically selects the next available odd stream ID after the highest configured priority stream.

### Header priority

`headers_priority` controls the priority associated with the request HEADERS stream.

Example:

```json
"headers_priority": {
    "exclusive": false,
    "depends_on": 0,
    "weight": 41
}
```

Fields have the same meaning as priority frames:

* `exclusive`
* `depends_on`
* `weight`

Set `headers_priority` to `null` when no custom header priority is required.

### END_STREAM on request HEADERS

`end_stream_on_headers` controls where `END_STREAM` is placed for requests that have no body.

When set to `true`:

```text
HEADERS + END_STREAM
```

is used for an empty request.

When set to `false`:

```text
HEADERS
DATA(length=0) + END_STREAM
```

is used instead.

For requests that contain a body, `END_STREAM` is sent on the final DATA frame and this option does not move it to the initial HEADERS frame.

This allows the HTTP/2 frame sequence to be matched to different client fingerprints.

### Pseudo-header order

`pseudo_headers_order` controls the order of HTTP/2 pseudo-headers in outgoing requests.

Supported pseudo-headers:

```text
:method
:path
:authority
:scheme
```

Example:

```json
"pseudo_headers_order": [
    ":method",
    ":path",
    ":authority",
    ":scheme"
]
```

The configured order is preserved when constructing the outgoing request.

### HTTP header order

`headers_order` controls the order of normal HTTP request headers.

Example:

```json
"headers_order": [
    "user-agent",
    "accept-language",
    "accept-encoding",
    "referer"
]
```

Headers listed here are processed in exactly this order.

### HTTP header modification

`http_headers` controls the values of individual HTTP headers.

A configured string value replaces the incoming value:

```json
"http_headers": {
    "user-agent": "Mozilla/5.0"
}
```

A header can be removed by setting its value to `null`:

```json
"http_headers": {
    "referer": null
}
```

Headers can also be added even when they were not present in the original request:

```json
"http_headers": {
    "priority": "u=0, i"
}
```

Headers that are not mentioned in `http_headers` are preserved from the incoming request.

This makes it possible to:

* replace existing headers;
* remove headers;
* add new headers;
* preserve unspecified incoming headers;
* control the final header ordering through `headers_order`.

For example:

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

In this configuration:

* `user-agent` is replaced;
* `accept-language` is replaced;
* `priority` is added;
* `referer` is removed;
* `accept` is preserved from the incoming request;
* the resulting headers follow the configured order.

### HTTP/2 request and response streaming

Request and response bodies are forwarded as streaming data rather than buffering the complete body in memory.

The proxy also preserves HTTP/2 trailing headers (trailers). When trailers are present, the final DATA frame does not carry `END_STREAM`; the trailing HEADERS frame closes the stream instead.

Without trailers:

```text
HEADERS
DATA
DATA + END_STREAM
```

With trailers:

```text
HEADERS
DATA
DATA
TRAILERS + END_STREAM
```
