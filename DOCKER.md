# Docker deployment

One hardened image, built from a static-Go Dockerfile:

| image target | binary | purpose |
| --- | --- | --- |
| `wan-ingress` | `cmd/wan-ingress` | WAN front: admit, resolve by agreement, sign and forward through the border |

The runtime stage is `gcr.io/distroless/static-debian12:nonroot`: one static
binary, no shell, no package manager, no writable root filesystem, UID 65532.
`cmd/healthcheck` is copied alongside so Docker can probe `/healthz` without
adding curl or wget.

The **seed/address plane** (`seed-invite`, `seed-announce`) is not in this
image. It ships from [lezz.go](https://github.com/james-gibson/lezz.go) and is
installed where the seed lives; this front stays unaware of DNS, mDNS and seed
semantics.

## Quick start

1. Fill in the operator-owned placeholders:

   ```sh
   cp configs/docker/wan-ingress.json configs/docker/wan-ingress.local.json
   cp configs/docker/agreements.json configs/docker/agreements.local.json
   # edit token, border key and border URL
   ```

   These files are **shapes**, not usable defaults. The token is a placeholder,
   so the front **refuses to start** until you replace it; the stack is
   fail-closed rather than fail-open. See [`SECURITY.md`](SECURITY.md).

2. Point the compose mount at your local copies (or edit the mounted files in
   place), then start:

   ```sh
   SMOKE_ALARM_URL=http://smoke-alarm:19100 docker compose up -d --build
   ```

   `cp .env.example .env` gives you the override set; `.env` is gitignored.

   `SMOKE_ALARM_URL` overrides the registry field in the config through an
   explicit flag, so the same mounted file works in several environments. The
   real border and the smoke-alarm registry are operator-supplied services; the
   example agreements point at `http://border:9443/cluster`.

3. Check the front:

   ```sh
   docker compose ps
   curl -fsS http://127.0.0.1:8443/healthz
   curl -fsS http://127.0.0.1:8443/readyz
   curl -fsS http://127.0.0.1:8443/status
   ```

The port defaults to `8443`; override with `WAN_INGRESS_PORT`.

## What "secured" means here

- **non-root** — the runtime uses UID/GID 65532.
- **no shell** — distroless static base; an attacker who gets a process cannot
  `sh`, `curl` or package-install their way sideways.
- **read-only rootfs** — only `/tmp` is a tmpfs; no config or binary is writable.
- **capabilities dropped** — `cap_drop: [ALL]`, `no-new-privileges: true`.
- **bounded** — `pids_limit: 64`, `mem_limit: 128m`, `cpus: 0.50`.
- **secrets outside the image** — the token and HMAC key live in mounted config
  files with `:ro`; no secret is baked into a layer. Use a secret manager or
  file-permission-controlled host mounts in production.
- **fail closed** — without agreements, token, border key and an agreed border,
  the front refuses or quarantines every call; with a placeholder secret it
  refuses to start at all.
- **TLS is not in this image's default** — the stack publishes plaintext on 8443
  and sets `allow_plaintext_wan`, which is the explicit statement that TLS is
  terminated in front. Terminate it, or mount a cert/key and drop that flag.

The boundary stays clean: the seed/address plane narrows the visitor, agreement
plus HMAC border decides what may cross.

## Builds

Local single-arch images are built by `docker compose build`. Multi-arch
`linux/amd64` + `linux/arm64` images come from the bake file:

```sh
docker buildx bake
# writes dist/wan-ingress.oci.tar (linux/amd64 + linux/arm64)
```

OCI archives are used instead of `type=docker` because Docker's local image
store cannot load multi-platform images. Import one platform with
`docker image load --input dist/wan-ingress.oci.tar` after export, or push from
your own registry pipeline. The same binaries are also emitted as static files
by `scripts/build-wan-ingress.sh` for non-container installs.

## Verify

```sh
docker compose config --quiet
docker buildx bake --print
go test ./... && go vet ./...
```

The feature file and isotope identity are unchanged; the image carries no spec
claim of its own.
