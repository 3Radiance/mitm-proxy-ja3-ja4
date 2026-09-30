# HTTP/2 Fingerprint Spoofing (Akamai)

[English](HTTP2.md) | [Русский](../ru/HTTP2.ru.md)

HTTP/2 fingerprinting (the Akamai-style hash over SETTINGS, window
sizes, priorities and header order) is fully configurable through the
`http2` section of the JSON profile. The proxy shapes the **upstream**
connection — preface, SETTINGS frame, stream priorities, header order —
while the browser-facing side just accepts what the client offers
(`src/h2_fingerprint/`).

## Connection flow

```
browser ──h2 handshake──▶ proxy ──h2 handshake (profiled)──▶ upstream
browser ──HEADERS───────▶ proxy ──HEADERS (reordered)──────▶ upstream
```

`handle_h2` runs both handshakes concurrently with a 5-second timeout
each: a plain server handshake toward the client, and a profiled client
handshake toward upstream built by `build_upstream_h2_builder`. Every
request is then rebuilt through `apply_http_headers` (order + values)
and sent upstream with the configured priority and `END_STREAM`
placement; bodies stream without buffering, trailers included.

If the upstream connection drops mid-request, the proxy reconnects
(`upstream_reconnect`, with the same TCP/TLS/HTTP2 profile — marked
socket included) and aborts on ALPN mismatch, so a reconnect can never
silently downgrade `h2` to `http/1.1`.

## Configuration (`http2` block)

```json
"http2": {
    "settings": {
        "header_table_size": 65536,
        "enable_push": false,
        "max_concurrent_streams": null,
        "initial_window_size": 6291456,
        "max_frame_size": 16384,
        "max_header_list_size": null
    },
    "settings_order": ["HEADER_TABLE_SIZE", "ENABLE_PUSH", "INITIAL_WINDOW_SIZE", "MAX_FRAME_SIZE"],
    "connection_window_update": 15663105,
    "initial_stream_id": null,
    "priority_frames": null,
    "headers_priority": { "exclusive": true, "depends_on": 0, "weight": 255 },
    "end_stream_on_headers": true,
    "pseudo_headers_order": [":method", ":authority", ":scheme", ":path"],
    "headers_order": null,
    "http_headers": {
        "user-agent": "Mozilla/5.0 (...)",
        "accept-language": "en-US,en;q=0.6"
    }
}
```

### `settings` — SETTINGS frame values

Values advertised in the upstream SETTINGS frame (`set_settings_frame`).
`null` omits the parameter entirely; `enable_push` is a plain bool and
always sent:

| Field | Meaning |
|---|---|
| `header_table_size` | HPACK dynamic table size. `null` = omit. |
| `enable_push` | Server push on/off. Always emitted. |
| `max_concurrent_streams` | Max concurrently active streams. `null` = omit. |
| `initial_window_size` | Per-stream flow-control window. |
| `max_frame_size` | Max frame payload size. |
| `max_header_list_size` | Max header list size. `null` = omit. |

If the whole `settings` object is missing, no values are customized and
the client's defaults apply.

### `settings_order` — SETTINGS parameter order

Order of parameters in the outgoing SETTINGS frame. Only parameters
present in `settings` are emitted, in exactly this order:

```
HEADER_TABLE_SIZE
ENABLE_PUSH
MAX_CONCURRENT_STREAMS
INITIAL_WINDOW_SIZE
MAX_FRAME_SIZE
MAX_HEADER_LIST_SIZE
```

Unknown names are a handshake-time error — the order list is validated
when the builder is created, so a typo fails fast on the first `h2`
connection instead of silently producing a wrong fingerprint.

### `connection_window_update` — connection window

`initial_connection_window_size` for the upstream connection: the
connection-level flow-control window, independent from the per-stream
`initial_window_size`. `null` (or missing) leaves the client's default.
Real browsers use distinctive large values here (e.g. `15663105` for
Firefox), so this field matters more than it looks.

### `initial_stream_id` — first request stream

Explicit first client-initiated stream ID. When `null`, it is derived:

- no priority frames → `1`;
- with priority frames → highest configured priority `stream_id` + 2
  (priority frames occupy stream IDs before the first real request).

When setting it manually alongside `priority_frames`, pick an unused odd
ID past them — a collision breaks the connection.

### `priority_frames` — pre-request PRIORITY frames

PRIORITY frames sent before normal request streams (the classic
Firefox/Chrome priority tree signal):

```json
"priority_frames": [
    { "stream_id": 1, "exclusive": false, "depends_on": 0, "weight": 41 },
    { "stream_id": 3, "exclusive": false, "depends_on": 0, "weight": 42 }
]
```

| Field | Meaning |
|---|---|
| `stream_id` | Stream the priority definition attaches to (client streams are odd). |
| `exclusive` | Whether the dependency is exclusive. |
| `depends_on` | Parent stream ID (`0` = connection root). |
| `weight` | Priority weight (1–256 on the wire; config uses the raw value). |

`null` or empty = no priority frames. With the example above and
`initial_stream_id: null`, the first request stream is auto-selected as
`5`.

### `headers_priority` — HEADERS stream dependency

Priority attached to each request HEADERS stream
(`headers_stream_dependency`):

```json
"headers_priority": { "exclusive": true, "depends_on": 0, "weight": 255 }
```

Same fields as priority frames, minus `stream_id`. `null` = no custom
dependency — the HEADERS goes out with defaults.

### `end_stream_on_headers` — END_STREAM placement

Where `END_STREAM` goes for requests **without** a body:

- `true` → `HEADERS + END_STREAM` (Firefox style);
- `false` → `HEADERS` then `DATA(length=0) + END_STREAM` (Chrome style).

Requests **with** a body always close on the final DATA frame — this flag
doesn't move that. The flag only fires when the incoming request itself
is end-of-stream, so it reshapes rather than invents stream closure.

### `pseudo_headers_order` — pseudo-header order

Order of `:method`, `:path`, `:authority`, `:scheme` in outgoing
requests. Unknown names fail the builder (fail fast, same as settings).
Browsers differ here characteristically — Firefox sends
`:method, :authority, :scheme, :path`:

```json
"pseudo_headers_order": [":method", ":authority", ":scheme", ":path"]
```

### `headers_order` + `http_headers` — headers

Two-stage pipeline (`apply_http_headers`):

1. Walk `headers_order`; for each name take the value from
   `http_headers` if configured (`"value"` = replace, `null` = remove),
   otherwise copy the incoming values through untouched.
2. Append configured headers not mentioned in the order (replacements
   only — `null` entries are skipped).
3. Append every remaining incoming header not seen yet.

```json
"headers_order": ["user-agent", "accept", "accept-language", "priority"],
"http_headers": {
    "user-agent": "Mozilla/5.0",
    "accept-language": "en-US,en;q=0.6",
    "priority": "u=0, i",
    "referer": null
}
```

Result: `user-agent` replaced, `accept-language` replaced, `priority`
added (Chrome's modern hint header), `referer` removed, `accept` passed
through from the browser, everything in the listed order. Headers absent
from both lists pass through in arrival order at the end. `null` for
both fields = byte-transparent passthrough.

### Streaming and trailers

Bodies stream in both directions — no full-body buffering. Trailer
handling follows the frames: with trailers the final DATA carries no
`END_STREAM`; the trailing HEADERS closes the stream:

```text
HEADERS → DATA → DATA + END_STREAM          (no trailers)
HEADERS → DATA → DATA → TRAILERS + END_STREAM (trailers)
```

## ALPS coupling

When `tls.alps` is `true`, the same `settings` + `settings_order` are
re-encoded as the TLS ALPS payload for `h2` (see `TLS.md`) — browsers
use that exact encoding, so one config drives both wire locations.
Keep them in sync with the target browser; a mismatch between the
SETTINGS frame and the ALPS payload is itself a fingerprint signal.

## Per-domain HTTP/2 (`-d domain.json`)

Any `http2` field can be overridden per domain pattern; `settings` ITS
sub-fields merge individually, everything else follows the standard
inherit-or-override rule (`null` resets). Since the builder is created
per upstream connection from the resolved profile, different domains
can present completely different Akamai hashes through one proxy
instance — pair with Multi-Account Containers on the browser side.

## Gotchas

- `settings_order`, `pseudo_headers_order` entries are validated —
  unknown names error the connection instead of degrading silently.
  Double-check spelling against the vocabularies above.
- `settings` values outside the protocol range (e.g. absurd
  `max_frame_size`) are rejected by the HTTP/2 stack at handshake time.
- `initial_stream_id` colliding with `priority_frames` IDs kills the
  connection — prefer `null` and let it derive.
- `end_stream_on_headers` only reshapes empty requests; bodied requests
  are unaffected by design.
- The browser-facing handshake is generic — the fingerprint you
  configure is what the **upstream** (and any checker behind it) sees.
  Validate with `tls.peet.ws`-style checkers through the proxy, not
  against the proxy's local port.
