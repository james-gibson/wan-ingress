# syntax=docker/dockerfile:1.7
#
# Hardened, multi-arch image for the WAN front. The runtime is a static Go
# binary on distroless nonroot: no shell, no package manager, no mutable
# runtime, and UID 65532. Build with buildx for linux/amd64+arm64.
#
# The seed/address plane is not in this image; it ships from lezz.go and is
# installed where the seed lives. This front stays unaware of DNS, mDNS and
# seed semantics.
ARG GO_VERSION=1.27.2

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/healthcheck ./cmd/healthcheck && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/wan-ingress ./cmd/wan-ingress

FROM gcr.io/distroless/static-debian12:nonroot AS wan-ingress
COPY --from=build /out/wan-ingress /wan-ingress
COPY --from=build /out/healthcheck /healthcheck
USER nonroot:nonroot
EXPOSE 8443
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD ["/healthcheck", "-url", "http://127.0.0.1:8443/healthz"]
ENTRYPOINT ["/wan-ingress"]
CMD ["-config", "/etc/wan-ingress/wan-ingress.json"]
