# The eight outcomes, after the changes

`le.critic` reports failure modes and verification criteria as `pass` / `drift` /
`violation` rather than a verdict, on the principle that a threshold claim is a
spectrum claim with the tail cut off. Its eight are about an FM carrier; this is
that discipline applied to the ingress, with the change that moved each row and
the evidence that would be accepted.

Nothing here says "safe". Each row is a position.

| outcome | before | after | what moved it |
| --- | --- | --- | --- |
| **jitter-vs-tampering alias** | drift | **drift** | Shape classes now separate *classes* (small/medium/bulk) and a declaration is scored against the body it carries (`shape_mismatch`). Heavy-versus-hostile inside one class is still aliased. |
| **tri-state collapse** | pass | **pass** | Decisions stay typed; `/status` reports `resolved`, `forwarded`, `border_seen`, `witness_gap` and quarantines by reason. `/readyz` is binary on purpose — it is the balancer's contract, not a collapse. |
| **side-channel bleed** | drift | **pass** | The shape budgets are published on `/policy`. A capacity that anyone can read cannot be discovered by probing, so the 429 carries no information that is not already public. `/resolve` still returns the agreed border address to a token holder — declared in the feature, and the token is the capability. |
| **sybil carrier flooding** | drift | **drift** | Bounded by `max_conns` and per-class budgets, refused rather than queued. Still one shared token and no per-caller identity; the excess waits in the kernel accept queue. |
| **mixed-stream separability** | pass | **pass** | Class selection is deterministic (declared class, else body length); refusals are typed and counted. |
| **demodulation threshold** | pass | **pass** | The concurrency knees are declared numbers in the grant, on a measured curve (1 KiB ~16, 64 KiB ~4, 1 MiB ~2–4), not a guessed rate. |
| **round-trip projection fidelity** | drift | **pass** | Two witnesses: the border echoes the canary and reports its own request count, and `/status` publishes `witness_gap`. A front that claims more forwards than the border saw now shows a gap instead of asserting success. |
| **forced-inclusion canary** | violation | **pass** | Every forward carries a random canary inside the signature; the border must echo it, and a missing echo is `502 canary_lost`, not a success. The marker must be carried forward or the call fails. |

Membership eviction is the remaining drift: a front whose policy isotope
diverges is *detectable* but nothing removes it from the routable set. The ban log
is the hook — it names the address and the reason, and the host decides.

## The evidence standard this does not yet meet

A critic that can be re-run and disagree with itself cannot be quoted. The
performance figures behind these rows are single runs, on a shared board, with
client and server co-located. They are directional, not publishable. The next
step for turning this into `le.critic` data is the lab's own methodology: seven
interleaved runs per cell, variance reported, on the two hosts separately.

## What moved, and where

| change | code |
| --- | --- |
| declaration scored against body | `internal/ingress/shapes.go`, `X-Lab-Shape` |
| budgets published | `internal/ingress/server.go` (`/policy`) |
| canary | `internal/ingress/forward.go`, `X-Lab-Canary` |
| second witness | `X-Lab-Seen`, `/status.border_seen`, `.witness_gap` |
| eviction hook | `internal/ingress/ban.go`, `-ban-log`, `-never-ban` |
