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
| stale captured envelope | `X-Lab-Timestamp` outside ±60s | border refuses | `harness/border_adapter_test.py` |
| a resolution counted as a forward | the monitor's green light | only `/forward` advertises `ingress/forward` | `TestResolveAloneDoesNotAdvertiseForwarding` |
| anonymous status scraping | `/status`, `/mcp`, `/readyz` | counters and readiness only; no route, address or namespace | `TestAnonymousSurfacesLeakNoRoute` |

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
3. **No rate limit.** An attacker can spend unlimited requests. With a 32-byte
   random token the guessing cost is prohibitive, so the residual is
   **availability**, not admission. Terminate at an edge that rate-limits, or
   accept the DoS surface.
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
9. **`addr` is not re-read on reload.** The listener is the deployment; the
   policy is what `SIGHUP` swaps. Changing `addr` in the file has no effect
   until a restart, which is logged.

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
