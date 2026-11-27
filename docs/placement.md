# Placement and capacity

Where the pieces go, why, and how a well-behaved ingress is allowed to go
faster than a new one.

Numbers here were measured on 2026-11-27 on a NanoPi R5S (RK3568, 4×A55 @2 GHz)
as the front and an i7-7700 as the neighbour/authority. They are recorded to
make the arithmetic checkable, not to be quoted as absolutes.

**Status.** The placement rule and the cgroup are deployment practice and apply
today. The ticket ring and the earned grant are the design's next step; they are
marked below so nobody mistakes a target for an implemented feature.

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

The soft limits therefore come from the **authority**, as a signed grant, not
from a local constant:

```json
{
  "namespace": "session-42",
  "batch": 1024,          // tickets in this grant
  "max_conns": 8000,      // concurrency the holder may admit
  "expires": 1767225600,  // tickets die with the grant
  "sig": "…"              // HMAC by the signing authority
}
```

The front admits `min(granted, local_hard_cap, cgroup)`. Three consequences:

- a well-balanced ingress — good rung, low 42i distance, probes passing —
  is **granted more**: a larger batch, more concurrency, a longer expiry. It goes
  faster because it has demonstrated it can.
- a new or flapping ingress is granted little. A crash loop is a flapping route;
  dampening suppresses it rather than banning it, and the penalty decays.
- the front cannot forge a grant. It holds tickets, not the key, so "go faster"
  is something the authority says, not something the front decides.

The hard ceiling does not move with standing. A proven ingress may use more of
the host; it may not take the host down, because the host is what holds the data
the standing is protecting.

This is the same structure as the address plane's pads: the burst limit is a
property of the credential supply, so there is no rate-limit threshold to tune —
and no threshold for an attacker to sit just under.

## 4. Ring arithmetic

A ticket ring is a cache between admissions and the authority. Its size is set by
two things, neither of which is bytes:

**Concurrency per signer round trip.** At dmz's measured 0.6 ms signer RTT, a
ring of **1** admits at most ~1,600 connections/s and queues everything behind
it. A grant of 64 absorbs a 64-connection burst with no queue and refills below
25%. A ring of 1 is therefore correct only for a low-arrival door, and it is
honest about what it is: one admission per signer round trip.

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
| ticket ring + earned grant | not implemented |
| splice mode | measured in a harness, not in the binary |

The next code change is inheriting the read/idle timeouts on any raw path (splice
mode); the grant format above is the design for the step after that.
