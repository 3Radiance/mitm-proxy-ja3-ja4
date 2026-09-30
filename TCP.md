# TCP (L4) Fingerprint Spoofing

[English](TCP.md) | [Русский](TCP.ru.md)

The proxy spoofs the TCP fingerprint of **outgoing upstream connections**
(TTL, window size, MSS, window scale, DF flag, TCP option order) by
intercepting packets in Linux Netfilter queues (NFQUEUE) and rewriting
them before they hit the wire. This covers the TCP layer of fingerprinting
(e.g. p0f-style signatures); TLS (JA3/JA4) and HTTP/2 (Akamai) are handled
by their own layers — see [TLS](TLS.md) and [HTTP/2](HTTP2.md).

## How it works

```
browser ──TLS──▶ proxy ──TCP+TLS──▶ upstream
                         │
              SO_MARK on upstream socket (e.g. 0x10)
                         │
              mangle/POSTROUTING ──mark 0x10──▶ NFQUEUE
                         │
              ┌──────────┴──────────┐
              │ qnum_syn (SYN only) │  rewrite window/TTL/DF/options
              │ qnum_tcp (rest)     │  rewrite TTL/DF only
              └──────────┬──────────┘
                    Accept, mark cleared ──▶ wire
```

1. Every upstream TCP socket is created with `SO_MARK` set to the profile's
   `mark` (`src/proxy/tcp.rs`). The mark is internal kernel metadata — it
   never goes on the wire; it only routes the packet to the right queue.
2. Two NFQUEUE consumers run in background tasks (`src/tcp_fingerprint/`):
   - `syn.rs` (`qnum_syn`) — handles **SYN without ACK** (connection
     opening) only. Rewrites window size, TTL, DF flag and rebuilds the
     TCP options in the configured order.
   - `tcp.rs` (`qnum_tcp`) — handles **everything else**. Only patches
     TTL (IPv4) / hop limit (IPv6) and the DF flag. Window and options are
     left untouched mid-connection, as a real stack would.
3. Every packet taken from a queue gets a verdict of `Accept` — including
   packets that don't match (non-SYN in the SYN queue, non-TCP, parse
   failures). A packet without a verdict stalls the queue forever, so the
   "accept everything by default, rewrite on match" shape is load-bearing.
4. After the verdict the fwmark is cleared (`set_nfmark(0)`), so the packet
   continues down the chain without the internal mark (no re-matching on
   mark rules below, nothing leaks into policy routing).
5. Checksums are always recalculated after a rewrite (TCP checksum over the
   pseudo-header + payload, IP header checksum). `total_len` is updated via
   `set_payload_len` when the TCP header size changes.

Per-mark profiles: the queue handlers pick a config by the packet's fwmark —
the domain config registered under that mark if one exists, otherwise the
default profile. The queues start when the base `mark` is set **or** any
domain overlay sets its own mark (`nfqueue_on = base.mark.is_some() ||
!tcp_domains.is_empty()`, `src/main.rs`). So a `null`/unset base `mark`
only leaves the *default* traffic unmarked (direct connects, no rewrite) —
marked domains are still rewritten.

## Requirements

- Linux with `iptables` / `ip6tables` (mangle table, NFQUEUE target).
- Root, or at least `CAP_NET_ADMIN` (`SO_MARK`, NFQUEUE bind, iptables).
  `CAP_NET_RAW` is also useful. See [Troubleshooting](#troubleshooting).
- Two **free** queue numbers. Do not reuse a queue owned by another tool
  (e.g. zapret/nfqws usually sits on `300`) — only one process can bind a
  queue number, the second bind fails.

## Configuration (`tcp` block)

```json
"tcp": {
    "mark": "0x10",
    "qnum_syn": 301,
    "qnum_tcp": 302,
    "auto_iptables": true,
    "ttl": 128,
    "window_size": 64240,
    "mss": 1460,
    "window_scale": 7,
    "dont_fragment": true,
    "timestamp": true,
    "tcp_options_order": ["mss", "sack_perm", "timestamp", "wscale", "nop"]
}
```

| Field | Type | Meaning |
|---|---|---|
| `mark` | hex string or int, optional | `SO_MARK` for upstream sockets and the mark the iptables rules match. `"0x10"` and `16` are the same. If unset, the TCP layer is off entirely (no queues, direct connects). |
| `qnum_syn` | int, optional | NFQUEUE number for SYN packets. Must differ from `qnum_tcp`. |
| `qnum_tcp` | int, optional | NFQUEUE number for established-flow packets. |
| `auto_iptables` | bool (default `false`) | Manage the mangle rules automatically (insert on start, delete on Ctrl+C). |
| `ttl` | int 0–255, optional | IPv4 TTL (IPv6 hop limit in the `tcp` queue). `null` = keep kernel value. |
| `window_size` | int, optional | TCP window (SYN only). Cast to u16. `null` = keep. |
| `mss` | int, optional | MSS value used when the `mss` option is emitted. Falls back to the kernel's value. |
| `window_scale` | int, optional | Same for the `wscale` option. |
| `dont_fragment` | bool (default `false`) | DF flag value written into SYN packets. |
| `timestamp` | bool (default `false`) | Whether the `timestamp` TCP option is emitted at all. `false` strips it even if listed in `tcp_options_order`; missing field also means `false`, so set it explicitly. |
| `tcp_options_order` | list of strings, optional | Rebuild SYN options from scratch in this order. `null` = keep kernel order, only patch MSS/wscale values. |

### `tcp_options_order` names

| Name (aliases) | Option emitted |
|---|---|
| `mss` | Maximum Segment Size (`mss` value or kernel's) |
| `wscale`, `window_scale`, `ws` | Window Scale (`window_scale` value or kernel's) |
| `sack_perm`, `sack`, `sack_ok`, `sack_permitted` | SACK Permitted |
| `timestamp`, `ts`, `timestamps` | Timestamps, kernel `tsval` / `tsecr=0` (only if `timestamp: true`) |
| `nop`, `noop` | Single NOP byte (padding/alignment) |

Unknown names are ignored. The encoder pads the options to a 4-byte
boundary automatically, so an explicit `"nop"` is how you reproduce
fingerprints like `mss,sack,timestamp,nop,wscale` — without it you'd get
zero (EOL) padding instead and a different signature.

## iptables management (`auto_iptables`)

When `true`, on startup the proxy ensures two rules per used mark
(default mark + every domain-overlay mark):

```
-mangle/POSTROUTING -p tcp --syn   -m mark --mark <M> -j NFQUEUE --queue-num <qnum_syn> --queue-bypass
-mangle/POSTROUTING -p tcp ! --syn -m mark --mark <M> -j NFQUEUE --queue-num <qnum_tcp> --queue-bypass
```

Details that matter when something else (zapret/nfqws, libvirt) also owns
mangle rules:

- Rules are inserted at the **top** (`-I POSTROUTING 1`), above third-party
  rules. Appending (`-A`) leaves them below e.g. nfqws, which then grabs
  the packets first and yours see zero traffic.
- Before inserting, all existing copies of the same rule are deleted, so
  restarts migrate rules left at the bottom by older versions and never
  stack duplicates.
- `--queue-bypass` lets packets through when no userspace reader is bound
  (proxy down) instead of stalling them in the kernel.
- The same pair is mirrored to `ip6tables` on a best-effort basis (failure
  is a warning, not fatal).
- On Ctrl+C the proxy deletes the rules it added (all copies) and then
  exits explicitly — the NFQUEUE loops block runtime workers in `recv()`,
  so a plain return from `main` would hang shutdown forever.

With `auto_iptables: false` nothing is touched: apply the two rules per
mark once by hand under sudo; they persist until reboot/flush.

## Per-domain TCP profiles (`-d domain.json`)

A domain overlay may carry its own `tcp` section. Merge semantics: every
field inherits the base value unless the overlay sets it — including
`mark` (an explicit `"mark": null` unsets it and opts that domain out of
rewriting). `qnum_syn`/`qnum_tcp`/`auto_iptables` are always shared from
the base profile. Every distinct mark gets its own iptables pair and its
own config branch in the queue handlers (`mark → TcpConfig` map,
`src/main.rs`, `src/tcp_fingerprint/iptables.rs`).

Base `mark` unset is a valid setup: the default traffic is then unmarked
(plain `TcpStream::connect`, no queue, no rewrite — `src/proxy/tcp.rs`),
but any domain that sets its own `mark` still gets `SO_MARK` on its
upstream sockets and its SYNs rewritten. This is how you rewrite only
selected domains while leaving everything else untouched, and route each
domain separately (`ip rule add fwmark <M> table <T>` / distinct gateways).

```json
{
    "tls.peet.ws": {
        "tcp": {
            "mark": "0x11",
            "ttl": 100,
            "window_size": 64130,
            "mss": 1400,
            "window_scale": 7,
            "dont_fragment": true,
            "timestamp": false,
            "tcp_options_order": ["mss", "sack_perm", "wscale", "nop"]
        }
    }
}
```

With this overlay only `tls.peet.ws` upstreams get `SO_MARK 0x11` and the
`ttl 100 / window 64130 / ...` rewrite; everything else follows the base
profile (unmarked and untouched when the base `mark` is `null`).

To reuse the same fingerprint on another pattern, just set the same
`mark` — no need to copy the full `tcp` block. When the base `mark` is
disabled, only the domain sockets are marked (each overlay's `mark` goes
to `SO_MARK` on its own upstreams), and the queue handlers pick the
rewrite by mark only. So a minimal `{"mark": "0x11"}` joins the same
rewrite/route branch as the domain that defines the full `0x11` profile,
and its TCP settings spill over from there:

```json
{
    "browserleaks.com": {
        "config": { "upstream_proxy": null },
        "tcp": {
            "mark": "0x11",
            "ttl": 100,
            "window_size": 64130,
            "mss": 1460,
            "window_scale": 7,
            "dont_fragment": true,
            "timestamp": true,
            "tcp_options_order": ["mss", "sack_perm", "wscale", "nop"]
        }
    },
    "*.browserleaks.*": {
        "config": { "upstream_proxy": null },
        "tcp": { "mark": "0x11" },
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

Notes on sharing a mark:

- One mark = one rewrite branch + one routing slot, by design. Queue
  handlers match **by mark only, not by SNI** (`tcp_domains.get(&mark)` in
  `src/tcp_fingerprint/syn.rs` / `tcp.rs`). That is what makes the
  minimal `{"mark": "0x11"}` form work — and what makes per-domain
  routing easy: one domain (or group) → one mark → one `ip rule` / table.
  Just don't put *different* `ttl`/options under the same mark: they
  share one branch, so keep the full block on one pattern and join it
  with a bare mark on the rest, or give each fingerprint its own mark.
- When the base `mark` **is** set, an overlay without its own mark
  inherits the base mark and intentionally falls back to the default
  branch (`if mark_c == mark { &default }` guard in `syn.rs` / `tcp.rs`),
  so its `ttl`/options overrides are ignored. This avoids routing
  ambiguity (same mark but different values). Want custom TCP values for
  a domain in that mode — give it a distinct mark.

### Policy routing by mark (e.g. via VPN)

A mark is both the rewrite key and a routing handle: one domain (or
group) → one mark → one `ip rule` / table. Example — send `0x11` via
`tun0`, everything else via the default route:

```bash
ip rule add fwmark 0x11 table 100
ip route add default dev tun0 table 100
```

Order matters, and it works in your favor: the `fwmark` routing decision
happens **before** `mangle/POSTROUTING` (i.e. before the NFQUEUE rewrite).
The queue handlers clear the mark to `0` after the rewrite
(`set_nfmark(0)`) only to avoid re-matching lower rules / loops — the
`SO_MARK` stays on the socket, so the next packet is born marked again
and routed the same way.

Caveat: if the profile sets `upstream_proxy`, **no marks are set at
all** — the upstream TCP connection terminates at that proxy (`CONNECT`
on a plain socket, `src/proxy/tcp.rs`), so there is nothing to rewrite
towards the real target anyway. Even if a mark were set, the SYN rewrite
would die on the proxy socket and never reach the origin — hence the
whole TCP layer is bypassed by design in this mode.

## Verification

```bash
# rules in place, ours on top?
sudo iptables -t mangle -S POSTROUTING
# counters grow under load? (run twice while curling through the proxy)
sudo iptables -t mangle -L POSTROUTING -v -n
# queues bound, packets flowing (not stuck)?
cat /proc/net/netfilter/nfnetlink_queue
# actual SYN on the wire matches the profile?
sudo tcpdump -i any 'tcp[tcpflags] & tcp-syn != 0' -v -c 5
```

## Troubleshooting

- **`Permission denied (you must be root)` on `iptables -A`** — the
  `nf_tables` backend wants real root even when `SO_MARK`/NFQUEUE work
  with file capabilities. Options: run under sudo / as a root systemd
  unit, or set `auto_iptables: false` and apply the rules once by hand.
- **Capabilities vanish after rebuild** — `cargo build` creates a new
  binary, file caps don't survive it. Re-apply
  `setcap 'cap_net_admin,cap_net_raw+ep'` after every build (check with
  `getcap`). On NixOS `/nix/store` is read-only — use
  `security.wrappers` instead. In containers you need
  `--cap-add=NET_ADMIN,NET_RAW`.
- **Our rules see 0 packets** — check in order: (1) test traffic really
  goes through *this* proxy; (2) `upstream_proxy` is `null` (otherwise
  marks are never set); (3) the SNI's domain overlay didn't drop the
  mark; (4) `ip6tables` counters too — the first DNS answer may be AAAA
  and the traffic IPv6.
- **`bind(queue) failed`** — the queue number is taken by another tool.
  Pick free numbers (see `/proc/net/netfilter/nfnetlink_queue`).
- **Handshake/`502` after enabling marks** — `SO_MARK` needs
  `CAP_NET_ADMIN`; the error surfaces as `Failed to set SO_MARK` /
  `Connection failure` in the logs.
