# The boundary, what it enforces, and what it does not

This is the threat model the front is built against, the attacks that were run
against it, and the residual risks an operator accepts by putting it on a WAN.
It is written to be falsified: every "enforced" row names the test that would
fail if the claim stopped being true.

## One sentence

A caller with the admission token may ask for an **agreed** name and send one
body through a **signed** envelope to the border that name points at — nothing
else. Everything the front decides is read from the operator's agreement file;
nothing is derived from the request.

That is a small boundary, which is the point. The token is not a password to a
service; it is a capability over a fixed routing table.

## The preflight (fail-closed)

`CheckDeployable` runs before the listener is opened and again on every SIGHUP.
It refuses to start rather than warn:

| condition | result |
| --- | --- |
| `addr` is not loopback and `token` is empty | refuse |
| `addr` is not loopback and `token` is under 32 bytes | refuse |
| `addr` is not loopback and `border_key` is under 32 bytes | refuse |
| `addr` is not loopback and no TLS, and `allow_plaintext_wan` is not set | refuse |
| `token` or `border_key` contains a placeholder (`REPLACE_WITH`, `CHANGEME`, …) | refuse anywhere |
| `tls_cert` set without `tls_key` (or the reverse) | refuse |

The published example config, run unchanged, **cannot start** — that is a test
(`TestShippedExampleConfigIsNotDeployable`), because a repository is public and a
placeholder is therefore a published credential. `-check-config` runs exactly
this check and exits, and `scripts/install-wan-ingress.sh` refuses to write a
supervisor unit around a config that fails it: a `KeepAlive` unit around a
refused config would restart forever and fill the log.

Loopback is exempt: local work stays one command, and the request path is still
fail-closed.

A non-loopback bind without a token is refused even though the request path
already refuses everything: a public listener that answers `403` to the world is
still a public listener, and it is exactly the shape a monitor should alarm on.

## Attacks run against it

| attack | mechanism | result | test |
| --- | --- | --- | --- |
| run the example as shipped | `configs/wan-ingress.example.json` | preflight refuses to start | `TestShippedExampleConfigIsNotDeployable` |
| weak/absent secrets on a public bind | `CheckDeployable` | refused (token and key ≥ 32 bytes) | `TestPublicBindRefusesWeakOrMissingSecrets` |
| plaintext on the WAN | TLS fields / explicit override | refused unless TLS or `allow_plaintext_wan` | same |
| no token | `Admit` | `403 untrusted`, no route learned | `TestAnonymousSurfacesLeakNoRoute` |
| wrong token, 300 guesses | `Admit` | `403` every time | probe, see *Measured* |
| caller names the destination | `X-Lab-Address` | ignored; path comes from the agreement | `TestCallerHeadersCannotReachTheBorder` |
| caller names the namespace | `X-Lab-Namespace` | overwritten from the agreement | same |
| caller forges the signature/timestamp | `X-Lab-*` headers | request is rebuilt; sync headers replaced | same |
| caller's credential travels onward | `Authorization` | not copied to the border | same |
| path traversal / encoded slash | `name=..%2fetc` | `422 malformed`, never read | `TestParseName`, `TestMalformedNameQuarantined` |
| double-decoded escape | `name=%2525` | `422 malformed` (one decode, then refuse `%`) | `TestEncodedPercentQuarantined` |
| NUL / control characters | `name=%00` | `422 malformed` | `TestParseName`, `TestMalformedNameQuarantined` |
| over-long name | 254 bytes | `422 malformed`, never truncated | `TestParseName` |
| oversized body | > 1 MiB | `422`, border never contacted | `TestOversizedBodyIsRefusedBeforeTheBorder` |
| duplicate `name` parameters | `?name=42&name=evil` | first wins for both resolve and forward | `TestDuplicateNameParametersResolveAndForwardTheSameName` |
| stale captured envelope | `X-Lab-Timestamp` outside the window | border refuses | `harness/border_adapter_test.py` |
| a route past its span | `X-Lab-Route-Start` | `422 route_dissolved`, border never contacted | `TestDissolvedRouteIsRefusedBeforeTheBorder` |
| two edges that disagree on "now" | stamped hop vs `peer_window_ms` | `422 clock_disagreement` | `TestPeerWindowRefusesAClockDisagreement` |
| a peer hop with no stamp | missing `@ms` | `422 clock_disagreement` — silence is not agreement | `TestUnstampedPeerHopIsADisagreement` |
| a hop backdating a route | the start is inside the signature | the border's signature check fails | `harness/border_adapter_test.py` |
| a resolution counted as a forward | the monitor's green light | only `/forward` advertises `ingress/forward` | `TestResolveAloneDoesNotAdvertiseForwarding` |
| anonymous status scraping | `/status`, `/mcp`, `/readyz` | counters and readiness only; no route, address or namespace | `TestAnonymousSurfacesLeakNoRoute` |
| a route that already contains this node | `X-Lab-Path` | `422 path_loop`, refused before the body and before the border | `TestRouteContainingThisNodeIsRefused` |
| an anonymous caller naming a node | `X-Lab-Path` from a non-peer | discarded; the path starts fresh at this node | `TestUntrustedPathIsDiscarded` |
| a client behind an nginx/LB naming a node | `X-Lab-Path` from the terminator | discarded — the terminator relays arbitrary clients, so its path proves nothing | `TestPathIsNotBelievedThroughATerminator` |
| a peer range that overlaps the terminator | `check-config` | refused at startup | `TestCheckDeployableRefusesAPeerInsideTheTerminator` |
| rewriting the path or the policy in transit | both are inside the HMAC | the border's signature check fails | `harness/border_adapter_test.py` |
| two nodes running different declarations | `GET /policy` | same declaration → same isotope; a difference is visible from outside either node | `TestTheSameDeclarationDerivesTheSameIsotope`, `TestADifferentDeclarationDerivesADifferentIsotope` |

### Grace and the span: two bounds, not one

A captured envelope is **replayable on purpose**. "Follow the cluster rules and
the path holds" is the stability promise: a negotiated route may be reused, and a
defence that refused reuse would break the thing it protects. So there are two
bounds, and they answer different questions.

| bound | scope | default | what it answers |
| --- | --- | --- | --- |
| **link window** (`--skew-ms`) | one hop | 5 s (the grace tick) | is this envelope too old for *this link*? |
| **route span** (`route_span_ms`) | the whole path | 15 s (three grace ticks) | has this route chained more grace than a path may spend? |
| **peer window** (`peer_window_ms`) | one edge link | 100 ms | do two adjacent edges agree on "now"? |

The link window is wide for cluster nodes because the grace tick is wide: a node
may present the previous tick's path. The span is what stops grace from chaining
forever — a route that outlives it **dissolves** (`422 route_dissolved`) rather
than being extended by another hop.

Measured across the LAN on 2026-11-27 (front on jack, border on dmz, span 15 s):
a route started 1 s ago, 14 s ago, and just now all pass; a route started 20 s
ago dissolves. Replay inside the span is accepted — that is the promise — and the
age is carried in the signature (`X-Lab-Route-Start`), so a hop cannot backdate a
route to keep it alive.

The 5 s tick is a *scheduling* window, not a ceiling on precision. The mechanism
supports far tighter links — 40/40 forwards passed at a **1 ms** window between
the two hosts — which is what an edge link should use when its path is short.
Cluster links stay wide:

| link | window |
| --- | --- |
| same host | ~1 ms (measured) |
| LAN edge | 25–100 ms (measured to 1 ms) |
| cluster node | 5 s (the grace tick) |
| route span | 15 s, then dissolution |

### The peer window is a jitter discriminator, not a tamper detector

The tight window between edges is the frequency discriminator: a hop carries the
instant it appended itself, and the next edge judges that stamp against its own
clock. That is what settles a wobble in one round trip instead of waiting for the
path to age out.

It is a **jitter** bound, and it has a measured false-positive curve. On dmz,
2,000 forwards per cell, a stamped peer hop on every request:

| peer window | c=8 dissolved | c=32 dissolved |
| --- | --- | --- |
| 1 ms | 1,685 (84%) | 1,880 (94%) |
| 5 ms | 64 (3.2%) | 1,168 (58%) |
| 25 ms | 0 | 33 (1.65%) |
| 100 ms | 0 | 0 |

The window must exceed **one-way delay + clock skew + the edge's queueing tail**,
not just the RTT: at c=32 this board's p99 is ~49 ms, so 25 ms holds at c=8 and
starts dissolving at c=32, while 100 ms holds at both. That is why the concurrency
cap and the shape budgets matter here too — bounding the queue bounds the jitter
tail, and a bounded tail is what lets the window be tight. Tight window, bounded
queue: wobble found fast. Wide window, unbounded queue: wobble hidden in the noise.

### Why a wobbling node destroys the path

The route's start travels inside the signature and is preserved by every hop, so
every hop ages the route by the same clock. A node whose clock wobbles either
presents a start in the future (refused) or one that has already outlived the
span (dissolved) — and because the start is shared, one bad node invalidates the
route for every hop downstream of it. That is the failure mode the span exists to
expose: not a hostile replay, but an honest path that quietly stopped being
current.

### Measured, not asserted

On 2026-11-26, against the binary on loopback:

- **4,335 authentication attempts/second** with no throttling, every one `403`.
  There is no rate limit and no lockout in the front.
- the shipped example config, unchanged, **bound `*:8443`** and accepted
  `Authorization: Bearer REPLACE_WITH_ADMISSION_TOKEN`, returning the agreed
  border address — before the preflight existed.
- one bare `/resolve?name=42`, with no body and no border call, made
  `initialize` advertise `ingress/forward` — before the counters were split.

Both are now tests, not anecdotes.

## Accepted risks (with the compensating control)

These are deliberate. They are listed so an operator decides, rather than
discovers.

1. **One shared bearer token.** No per-caller identity, no mTLS, no key
   rotation. Compensation: 32-byte minimum and a placeholder refusal; the token
   must be generated (`openssl rand -base64 32`), not chosen. Rotation is a
   config reload away, but it is all-or-nothing.
2. **The token reads the map.** `/resolve` returns the border address and
   namespace to any token holder. That is declared in the origin feature
   (`Scenario: a known name resolves to an agreed border address and
   namespace`), so the token is a topology-read capability, not just admission.
   Treat a leaked token as a leaked map.
3. **No rate limit and no connection bound.** Admission is not the residual —
   a 32-byte token makes guessing prohibitive. The residual is **availability**,
   and the resource that matters is not upstream: a refused caller never reaches
   the border, so upstream bandwidth cannot bound the refusal path. The two
   paths consume disjoint resources.

   Measured on loopback (2026-11-26, front and client sharing one machine, so
   the server's share is smaller than these wall-clock numbers):

   | path | rate |
   | --- | --- |
   | refused, keep-alive | ~60,000 req/s |
   | refused, fresh TLS per request | ~3,556 req/s |
   | accepted, 1 MiB body | ~1,610 req/s (1.6 GiB/s) |
   | accepted, 1 KiB body | ~13,820 req/s |

   A refusal is cheap; a *handshake* is ~17x a refusal. So the expensive thing
   an anonymous caller does is not "be refused", it is "make the front do a
   handshake" — which is why the first control is a connection bound, not a
   request-rate bucket. The accepted path is bounded by the border's capacity
   and by bytes/s, so a request limit there is fairness, not defence.

   The cheap refusal is a property to keep: the 403 reads no body and writes no
   log line. Adding a synchronous access log before the auth check would make
   the log the amplifier.
4. **No per-caller audit log.** `/status` counts decisions by reason, not by
   caller. If you need attribution, log at the edge or in the border.
5. **The registry is trusted and unauthenticated.** `Register`/`Deregister`
   carry no token in this repo (`smoke-alarm` owns that surface). Anyone who can
   reach the registry can re-point or delete the `wan-ingress` name. Keep the
   registry loopback/LAN-only; it is a naming authority, not a public service.
6. **Replay inside the border's window.** The ingress signs each forward; the
   border accepts it for ±60s. An attacker who has stolen a token can replay
   their own calls — it adds no capability they did not already have — but a
   captured envelope is a 60-second re-playable artifact. The border's window is
   the knob, not the ingress's.
7. **Certificate rotation needs a restart.** `SIGHUP` swaps policy, not the TLS
   certificate loaded by `ServeTLS`.
8. **HTTP/1.1 and HTTP/2 by default.** No cipher allow-list, no HSTS, no OCSP
   stapling. Terminate TLS at an edge if you need that policy surface.
9. **A path is trusted by address, not by signature.** A peer is believed
   because its TCP address is configured; a terminator is never believed. That
   is the right split for a load balancer, but it means the *peer* set is a
   credential-equivalent: anyone who can source traffic from a peer address can
   write a path. The correct long-term form is a scoped credential per hop
   (`lab/SPLASH.md` *Transport assumptions*: token exchange, DPoP, mTLS), so the
   path carries its own proof and the source address stops mattering.
10. **Peers are trusted by address, not by credential.** A path is believed when
   the TCP peer is inside a configured CIDR. A spoofed source cannot complete a
   handshake, so this is stronger than it sounds, but a compromised host inside
   the range can write a path — and a path is evidence, not authority
   (`lab/SPLASH.md`: *holding an isotope is not reachability*). If a peer set is
   configured, give each peer its own credential rather than relying on the
   network location.
11. **`/policy` is public.** It publishes a derived digest and two counts, never a
    route, address or namespace. A digest is a confirmation oracle for a guessed
    declaration; the declaration is operator-owned and the token is the secret,
    so the disclosure is bounded — but it is a disclosure.
12. **The policy isotope detects divergence; it does not resolve it.** A node
    with a stale declaration reports a stale isotope, which is the point, but
    the front does not refuse to serve on a mismatch — it has nothing to compare
    against. The border or a peer does the comparison.
13. **`addr` is not re-read on reload.** The listener is the deployment; the
   policy is what `SIGHUP` swaps. Changing `addr` in the file has no effect
   until a restart, which is logged.

## Capture mode

`-dump-unexpected` writes refused requests to a file. It is a deliberate
exposure: the file is attacker-controlled text, so it is JSON-encoded, length
capped, rate limited, and **never includes `Authorization`, `Cookie`,
`Set-Cookie` or `X-Api-Key`** (`TestDumpNeverWritesTheToken`). Pointed at an empty
gateway it records what the internet says to an unconfigured host; pointed at a
live gateway it records the requests the gateway did not expect.

## Eviction

Refusals are counted per address and, past a threshold in a window, written to a
line a host filter can read:

```
2026-11-27T04:20:00Z wan-ingress ban ip=192.0.2.5 reason=untrusted count=20
```

A fail2ban filter:

```ini
[Definition]
failregex = ^.*wan-ingress ban ip=<HOST> reason=[a-z_]+ count=\d+$
```

`never_ban` is the allowlist. Put the jump host in it — a ban on the machine an
operator reaches the lab through removes the way to undo the ban. Enforcement is
deliberately outside the front: a bad threshold must not be able to lock an
operator out of the fix.

## Before you put it on a WAN

- [ ] `token` and `border_key` generated, ≥ 32 random bytes, and not in git
- [ ] `tls_cert`/`tls_key` set, or `allow_plaintext_wan` with TLS terminated in
      front of it — and you have written down which
- [ ] agreements reviewed: every alias is a route you would give the token
      holder
- [ ] the border enforces the timestamp window (the reference adapter does)
- [ ] the registry is **not** reachable from the WAN
- [ ] a rate limit exists somewhere in front (edge, LB, or the border)
- [ ] the smoke-alarm target is pointed at this instance, so *yellow* means
      "never forwarded" and *green* means it has
- [ ] `/status` scrape and alerting wired: a rising `untrusted` count is the
      signal you care about

## Running the adversarial suite

```sh
go test ./internal/ingress -run 'TestShipped|TestPublicBind|TestLoopback|TestResolveAlone|TestCallerHeaders|TestOversized|TestDuplicate|TestAnonymous' -v
cd harness && python3 -m unittest border_adapter_test -v
./scripts/build-wan-ingress.sh
```

The full live harness (`harness/spike.sh`, `harness/blue_adhd_proxy_test.py`)
needs the lab's smoke-alarm and adhd spin harnesses; it exercises the boundary
against the real instruments rather than httptest doubles.
