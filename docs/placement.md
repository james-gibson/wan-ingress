# Placement and capacity

Where the pieces go, why, and how a well-behaved ingress is allowed to go
faster than a new one.

Numbers here were measured on 2026-11-27 on a NanoPi R5S (RK3568, 4×A55 @2 GHz)
as the front and an i7-7700 as the neighbour/authority. They are recorded to
make the arithmetic checkable, not to be quoted as absolutes.

**Status.** The placement rule and the cgroup are deployment practice and apply
today. The signed grant is implemented (`internal/ingress/grant.go`,
`cmd/wan-ingress-grant`) and is enforced live, including per-shape budgets. The
ticket ring is specified but not implemented, for the reason given in §4.

---

## 1. The rule: growing state goes on the host with nothing to steal

| role | footprint under attack | placement |
| --- | --- | --- |
| front, splice, relay, caches, connection pools, ticket ring | grows with every client | **dmz** — no data |
| signing authority, border, key custody | one MAC per request, fixed footprint, no per-client state | **jack** — may hold data |

A front is a point of origin, not a store. It holds no authoritative state: the
route table is derived from the agreement file at boot, and the policy isotope is
therefore identical after a restart. What it does hold — connections, buffers,
caches, tickets — is attacker-influenced, so it belongs on the host whose
compromise costs availability and nothing else.

The data-bearing host runs fixed-footprint roles only. It answers small messages
and holds the key; it does not accumulate per-client memory.

## 2. The hard ceiling is not negotiable

The host must survive whatever the front is doing. That is a cgroup, not an
in-process promise:

```ini
MemoryMax=256M
TasksMax=256
Restart=always
RestartSec=200ms
```

Measured: a held half-open connection costs **~12 KB** of front memory. 1,000
held connections peaked at 16–19 MB. The shipped front drops them at its 5 s
`ReadHeaderTimeout`; a raw splice path has no such deadline unless it inherits
one, and then 100,000 connections is ~1.2 GB on a 3.9 GB board — a host event,
not a process event.

So:

- the cgroup makes an overrun a **restart**, not a host failure;
- an in-process `max-conns` makes the footprint predictable (`cap × 12 KB`) and
  keeps the restart from becoming a loop;
- both are required when the front is anywhere near data.

Neither is a performance knob. They are the wall.

## 3. Capacity above the floor is earned, not configured

SPLASH, *Metering*: **the supply is earned** — "a cluster that behaves at scale
may write more pads… a misbehaving cluster cannot mint."

The softer limit therefore comes from the **authority**, as a signed grant, not
from a local constant:

```json
{
  "version": "wan-ingress-grant-v2",
  "namespace": "session-42",
  "batch": 1024,            // tickets in this grant
  "max_conns": 8000,        // connections the holder may admit
  "shapes": [               // per-body-class concurrency budgets
    { "class": "small",  "max_bytes": 16384,   "max_conns": 16 },
    { "class": "medium", "max_bytes": 262144,  "max_conns": 8  },
    { "class": "bulk",   "max_bytes": 1048576, "max_conns": 4  }
  ],
  "expires": 1795755304,
  "issuer": "jack",
  "signature": "…"          // Ed25519 by the signing authority
}
```

The front admits `min(granted, local_hard_cap, cgroup)`.

**Ed25519 rather than an HMAC.** Verifying an HMAC requires the key, and a holder
of the key can mint. A front that verifies with a public key can check a grant
but cannot produce one — so "go faster" is a statement the authority makes, not a
decision the front takes. The signature covers every field that grants anything:
namespace, batch, ceiling, expiry and issuer. Editing any of them invalidates it.

Raising capacity does not need a restart: a renewed grant is re-read on `SIGHUP`
and applied to the listener live (measured: 2 → 5,000 connections on one signal,
no dropped admission).

Three consequences:

- a well-balanced ingress — good rung, low 42i distance, probes passing —
  is **granted more**: a larger batch, more concurrency, a longer expiry. It goes
  faster because it has demonstrated it can.
- a new or flapping ingress is granted little, and a grant that fails to verify
  degrades the front to 64 connections until it is renewed — logged, not fatal,
  because a front is supposed to restart and keep serving.
- the front cannot forge a grant. It holds a public key, not the private one.

The hard ceiling does not move with standing. A proven ingress may use more of
the host; it may not take the host down, because the host is what holds the data
the standing is protecting.

This is the same structure as the address plane's pads: the burst limit is a
property of the credential supply, so there is no rate-limit threshold to tune —
and no threshold for an attacker to sit just under.

## 4. Ring arithmetic

A ticket ring is a cache between admissions and the authority. Its size is set by
two things, neither of which is bytes:

**Concurrency per round trip.** At dmz's measured 0.6 ms authority round trip, a
ring of **1** admits at most ~1,600 connections/s and queues everything behind
it. A batch of 64 absorbs a 64-connection burst with no queue and refills below
25%. A ring of 1 is therefore correct only for a low-arrival door, and it is
honest about what it is: one admission per authority round trip.

**Why the shape budgets are sized that way.** The concurrency knee is a property
of the body class and the board, not a preference. Measured on dmz:

| body class | knee | T at knee | at c=8 |
| --- | --- | --- | --- |
| 1 KiB | ~16 | 1,690/s | 1,504/s |
| 64 KiB | ~4 | 608/s | 623/s (+2%, p95 4× worse) |
| 1 MiB | ~2–4 | 131/s | 137/s (+5%, p50 1.9× worse) |

Small requests are syscall-bound and need more in flight to fill the pipe; bulk
requests are hash-bound and saturate as soon as the cores are busy. A single
concurrency number is therefore wrong for every class: sized for 1 KiB it
over-provisions bulk 4–8×; sized for bulk it queues small requests at a quarter
of their capacity.

**Classification is by `Content-Length`, before the body is read.** A request
whose length is unknown (chunked) or larger than the biggest class takes the
largest class, which carries the tightest budget. A request that would exceed its
class is refused `429` with `Retry-After: 1` and counted as `shape_full` — refused
rather than queued, because queueing a body is the memory the budget exists to
bound. Verified on dmz: a 1 MiB flood at concurrency 8 against a bulk budget of 4
produced 50 successes and 150 `shape_full`, with zero bodies held.

The front does not invent budgets. A grant with no `shapes` means no per-class
enforcement, because shape is an expectation the authority states, not one the
front assumes.

**Why the ring is still specified and not built.** A ticket is only meaningful
where it is *checked* — at the border — and the batch bound can only be enforced
where a per-grant counter lives. Deriving tickets from a seed in the grant lets
the front derive any index it likes, so the batch limit would be decorative. The
ring therefore waits for the border-side counting decision; until then the grant's
`max_conns` and `expires` carry the earned-capacity property on their own.

**Theft radius.** A stolen batch is usable until expiry, so exposure is
`batch × TTL`, not `batch`. Prefer many short-lived tickets over few long-lived
ones, and scope each to a namespace.

Memory is never the constraint: 1,024 tickets is ~100 KB.

Measured cost of consuming a ticket per **request** rather than per
**connection**: 1,214/s (unix socket) and 1,383/s (remote authority) against
1,685/s in-process, at 1 KiB and c=8. Per connection, arrival rate is a small
fraction of request rate, so a modest ring costs nothing visible.

Because a front restarts in 40 ms, an empty ring is a cold start worth one signer
call. Nothing about the ring needs to survive the process.

## 5. The restart contract

Measured on dmz: **39–40 ms** from launch to `healthz 200`.

So the lifecycle is replace, not drain:

- in-flight connections die; clients retry and land on another door;
- the agreement file re-derives the same policy isotope, so provenance is
  restored without any stored state;
- the ticket ring is cold for one signer call;
- the load balancer takes the door out on `/readyz` and puts it back on the same.

A crash is a door flap, not an outage — provided there is more than one door and
the balancer is checking `/readyz` rather than assuming.

What must survive a restart: nothing. If something must, it was state on the
wrong host.

## 6. The authority is a policy point, not an oracle

A data-free front that can ask a data-bearing authority for signatures is a
confused deputy. If the front is compromised, it can ask for anything.

The grant closes this by construction:

- the authority signs a **batch for a namespace with a TTL**, not arbitrary
  canonical strings;
- the front can spend its batch and no more;
- it cannot widen the namespace, extend the expiry, or mint a new batch.

A per-request MAC endpoint is the wrong shape for the same reason: it makes the
authority a general signing oracle and puts an RTT in front of every request.

---

## What is implemented today

| element | state |
| --- | --- |
| policy isotope, signed path, terminator split | implemented (`feat/policy-and-path`) |
| fail-closed preflight, TLS, reconnect hygiene | implemented (`security/wan-readiness`) |
| cgroup / `Restart=always` | deployment practice — the unit files do not set limits yet |
| `max-conns` | implemented (`-max-conns`, applied at the listener) |
| signed grant (Ed25519) + live renew | implemented (`-grant`, `-grant-key`, `cmd/wan-ingress-grant`) |
| per-shape budgets + edge classifier | implemented (`shapes` in the grant, `429 shape_full`) |
| ticket ring | specified, not implemented — needs border-side counting (§4) |
| forced-inclusion canary | implemented (`X-Lab-Canary`, echo required, `canary_lost`) |
| second witness | implemented (`X-Lab-Seen`, `/status.border_seen`, `.witness_gap`) |
| declared shape | implemented (`X-Lab-Shape`, `shape_mismatch` / `shape_unknown`) |
| eviction hook | implemented (`-ban-log`, `-never-ban`; enforcement stays on the host) |
| splice mode | measured in a harness, not in the binary |

The next code change is inheriting the read/idle timeouts on any raw path (splice
mode), then the ticket ring once the border-side counter is decided.
