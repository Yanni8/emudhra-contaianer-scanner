# syntax=docker/dockerfile:1

# Build stage. It always runs on the build host's platform and cross-compiles
# for the target, so multi-platform builds need no emulation: the binary is
# pure Go and CGO is disabled. The newest stable Go builds releases; go.mod
# stays the minimum version.
FROM --platform=$BUILDPLATFORM golang:1-alpine AS build

WORKDIR /src

# Module downloads get their own layer so that source changes do not repeat them.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
# Shown by "emudhra-container-scanner version"; the release workflow passes the git tag.
ARG VERSION=dev

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/emudhra-container-scanner .

# Runtime stage. Distroless static ships the CA certificates the scanner needs
# to reach registries, tzdata and a non-root user (uid 65532), and nothing
# else. Debian 13's ca-certificates no longer trusts the roots behind the
# compromised eMudhra CAs, so this image passes its own scan; the Debian 12
# variant still trusts them and would fail the release workflow's self-scan.
FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=build /out/emudhra-container-scanner /usr/local/bin/emudhra-container-scanner

# Mount point for local images (--input) and reports.
WORKDIR /work

ENTRYPOINT ["/usr/local/bin/emudhra-container-scanner"]
