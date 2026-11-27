# wan-ingress

> A thin WAN-facing front that resolves essentially any inbound name into
> **agreed** cluster addresses and namespaces, and forwards only through a
> signed border. It does not route by guessing.

One static Go binary, pure standard library. Installs as one file plus a JSON
config and its agreement file.

| field | value |
| --- | --- |
| isotope (origin feature) | `GBcFWtOHS-vATnxi4dpiILyggRECufP3MrlYkVMuGSs` |
| signature prefix (key `seed-42`) | `7a2f99d42815076c…` |
| tokens / parts | 149 / 26 |

The origin is [`features/wan-ingress.feature`](features/wan-ingress.feature),
written and validated before the first line of Go.
[`internal/ingress/spec_test.go`](internal/ingress/spec_test.go) re-reads it with
`isotope.ParseGherkin` + `CanonicalizeGherkinToIsotope`, so the declaration and
the code cannot drift apart. The file is byte-identical to the one the
shell-to-gherkin canon validated, and the signature above is reproduced by
`isotope v0.6.0`.

## The two gates

- **G1 — scope:** WAN front → lab border. The public side has thin admission;
  isotope rungs and the BAML border remain authority inside the lab.
- **G2 — resolver:** accept all, quarantine unknowns. Parsing is total;
  forwarding needs an agreement. Unknown, ambiguous and malformed inputs get a
  typed refusal; addresses and namespaces come only from the operator's
  agreement file.

## Surface

- `GET /healthz` → `200 ok` with no configuration
- `GET /readyz` → `200 ready` only with token and border key
- `GET /resolve?name=<raw>` → agreed route, or `422` with `malformed` / `unknown` / `ambiguous`
- `POST /forward?name=<raw>` → HMAC-signed border envelope, or a typed refusal
  (`border_unconfigured` included); caller-supplied address headers are ignored
- `GET /status` → resolved and forwarded counts, and quarantines by reason
- `GET /policy` → the derived isotope of the agreement file, and its size; never
  a route, address or namespace
- `POST /mcp` → JSON-RPC probe surface for smoke-alarm (`initialize`,
  `ingress/status`, `notifications/initialized`)

Defaults are deliberately fail-closed: no agreements, token or key means the
process answers health/status and refuses everything else.

## It is monitored, not self-reporting

[`configs/wan-ingress-alarm.yaml`](configs/wan-ingress-alarm.yaml) is a
smoke-alarm target that probes `POST /mcp` with a JSON-RPC handshake and
requires `ingress/forward` in `min_capabilities`. The front advertises that
capability **only after an agreed request has actually crossed the signed
border**. So the lab's own instruments see:

| state | alarm | adhd light |
| --- | --- | --- |
| answers, never forwarded | degraded | **yellow** (defensive) |
| has forwarded | healthy | **green** |
| process is gone | regression / unhealthy | **red** |

[`harness/spike.sh`](harness/spike.sh) drives the real smoke-alarm and adhd spin
harnesses through `dark → yellow → green → red` and asserts every hop from the
monitor's status and adhd's light log — not from the front's `/healthz`.

No caller carries the ingress URL. The listener address is only a binding; the
front's address is the isotope name `wan-ingress`. The harness's
[`harness/proxy/`](harness/proxy/) stands in for another cluster's egress/alarms:
it resolves that name from the registry and forwards both the probe and the
data-plane call. It is harness-only; the shipped binary is unchanged and stays
unaware of addressing beyond its agreements.

A blue-team baseline
([`harness/blue_adhd_proxy_test.py`](harness/blue_adhd_proxy_test.py)) puts two
caller adhd proxies on the same generation: one reaches a target directly, the
other by invite through the ingress and a signed harness border. Both call the
same `adhd.proxy` method, so only the boundary varies. Unsigned border copies,
tokenless callers and unagreed names are refused; the measured latency is
reported as the cost of the boundary, not as the security finding. A second run
compares held connections against new ones: holding reuses one ingress↔border
and one border↔target connection across 60 calls, while the new-connection mode
opens 61 of each and shows the churn cost.

## In a sub-cluster

A path vector, so a route cannot contain itself (`lab/SPLASH.md` → *The proxy*;
`lab/SLA.md` §12):

```json
{ "node": "wan-a", "peers": ["10.0.0.0/24"], "terminator": ["10.0.0.5"] }
```

Behind an nginx or a cloud load balancer, every client shares the terminator's
source address. `terminator` names it so its traffic is **not** trusted as a
peer's: a path from the terminator is a client's header and is discarded. A
range listed in both is refused at startup, because that is exactly the
configuration where a client's path would be believed.

- every forward appends this node to `X-Lab-Path`, which is inside the signature;
- a route whose path already contains this node is `422 path_loop`, refused
  before the body is read and before the border is contacted;
- a path is believed only when the TCP peer is in `peers` — otherwise an
  anonymous caller could name a node and have it refuse on someone else's behalf.

And the declaration is *derived, not stored*: every node reports the isotope of
the agreement file it is running at `GET /policy`, so two nodes that disagree are
visible from outside either of them. That is a cheap equality test in place of
fast gossip — you do not need convergence to be invisible if divergence is
observable.

## Capacity is granted, not configured

A new ingress serves a small default. Capacity above it is something the
authority says, in a signed grant:

```sh
wan-ingress-grant -keygen                      # once, on the authority
wan-ingress-grant -key <b64> -namespace session-42 \
  -max-conns 8000 -batch 1024 -ttl 1h -out grant.json
```

```json
{ "addr": "0.0.0.0:8443", "grant": "/etc/wan-ingress/grant.json",
  "grant_key": "<authority public key>" }
```

The front verifies with the **public** key and cannot mint: an HMAC would let a
front that can check a grant also forge one. The grant covers namespace, batch,
connection ceiling and expiry, and a renewed grant is applied on `SIGHUP` —
2 → 5,000 connections on one signal, no restart and no dropped admission. A
grant that fails to verify degrades the front to 64 connections and says so,
rather than failing to start.

[`docs/placement.md`](docs/placement.md) has the reasoning: what belongs on the
data-free host, the cgroup that makes "it restarts" true without taking the host
down, and why the ticket ring waits for a border-side counter.

## Self-healing

- the registry name is renewed on a heartbeat (`-heartbeat`, default 1m, inside
  smoke-alarm's 5m TTL); a failed beat is logged and retried, never fatal
- a clean signal drains the listener and sends the registry a delete; a crash
  leaves the lease to the TTL sweep
  ([smoke-alarm#112](https://github.com/james-gibson/smoke-alarm/issues/112)
  tracks adding the missing delete route; until then the delete is best-effort)
- `SIGHUP` reloads the config and agreements atomically: new traffic can be
  added without a restart, counters survive the swap, and a bad file keeps the
  last good policy
- [`scripts/install-wan-ingress.sh`](scripts/install-wan-ingress.sh) installs a
  launchd `KeepAlive` agent on macOS or a systemd `Restart=always` user unit on
  Linux, so a crash is restarted by the host

## Install

Network access alone produces a fail-closed listener. The install script
refuses to run without `CONFIG`, and the binary refuses to start on a config
that would be a public credential:

```sh
cp configs/wan-ingress.example.json configs/wan-ingress.json
cp configs/wan-ingress-agreements.example.json configs/agreements.json
# generate the two secrets — do not choose them
openssl rand -base64 32   # token
openssl rand -base64 32   # border_key
# fill in the border URL, the registry URL, and (for a public bind) tls_cert/tls_key

BINARY=./dist/wan-ingress-darwin-arm64 CONFIG=./configs/wan-ingress.json \
  ./scripts/install-wan-ingress.sh
```

A non-loopback bind is refused unless the token and border key are at least 32
bytes each **and** TLS is configured (or `allow_plaintext_wan` says TLS is
terminated in front). Placeholder values are refused everywhere. This is a
preflight, not a warning: the process exits with the reason and the fix.

`./scripts/build-wan-ingress.sh` produces statically linked, stripped binaries
for darwin/linux × amd64/arm64 with SHA-256SUMS. `DOCKER.md` covers the
distroless image and the hardened Compose stack.

## The address plane is not in this repo

Resolving an invite to a binding, and requiring a signed rotational
announcement before a call is forwarded, belongs to the seed the name belongs
to. That plane ships from
[lezz.go](https://github.com/james-gibson/lezz.go)
([`docs/seed.md`](https://github.com/james-gibson/lezz.go/blob/main/docs/seed.md#the-address-plane)):
`seed-announce` signs a rotation, `seed-invite` arms a one-shot expectation and
forwards with the operator token. This front sees an ordinary agreed call and
knows nothing about DNS, mDNS, seeds or slots.

A rotation ticket is evidence of an arrival, never a bearer credential.
`internal/ingress` refuses any caller whose token is not the configured one,
whatever headers travel with it; that is asserted in
[`internal/ingress/ticket_test.go`](internal/ingress/ticket_test.go).

## Verification

- `go test ./...` — green, including the adversarial suite in
  [`internal/ingress/redteam_test.go`](internal/ingress/redteam_test.go)
- `go vet ./...` and `golangci-lint run` — clean
- `python3 -m unittest discover -s harness -p '*_test.py'` — the border's
  freshness and signature contract
- `./wan-ingress -check-config -config <file>` — the deployment preflight
  (refuses placeholders, weak secrets and plaintext public binds)
- five fuzz targets: `FuzzResolveName`, `FuzzQuarantineContract`,
  `FuzzBorderForward`, `FuzzCanonicalize`, `FuzzConfig`. Two parts of the
  feature are fuzz regressions: `"0 ."` was canonicalised with a trailing space
  on one read and differently on the next (fixed by trimming to a fixed point),
  and `%25` decoded to a canonical `%` that then failed to reparse (fixed by
  refusing a decoded percent). Both crashers are kept in `testdata/fuzz/`.
- `go test ./...` includes the shipped example's refusal
  (`TestShippedExampleConfigIsNotDeployable`), so a public credential cannot be
  merged back in
- `ocd-smoke-alarm validate -config configs/wan-ingress-alarm.yaml` — valid
- `harness/spike.sh` — PASS, with the light transitions recorded above
- [`.github/workflows/ci.yml`](.github/workflows/ci.yml) enforces the PR 30s
  fuzz smoke, the 10m nightly fuzz on Linux/macOS, the cross-build matrix and
  the image build

Refusals are observable on `/status`; the registry (not the binary) judges the
trust rung, and the alarm (not the binary) judges health.

## Security

[`SECURITY.md`](SECURITY.md) is the threat model: the attacks that were run
against this binary, the tests that pin each outcome, the measured results, and
the residual risks an operator accepts by putting it on a WAN. Read it before
you expose the port.

The short version: the token is a capability over a fixed routing table, not a
password. It admits, it reads the agreed border addresses, and it forwards —
so treat a leaked token as a leaked map. There is no rate limit and no per-caller
audit log in the front; put it behind an edge that has both.

## Provenance

Designed on [lab-safety#38](https://github.com/james-gibson/lab-safety/issues/38)
and first written in [lab-safety#39](https://github.com/james-gibson/lab-safety/pull/39).
Moved here, with the seed/address plane split out to lezz.go, so the lab keeps
one repository per tool.
