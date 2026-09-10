FROM golang:1.27-bookworm AS builder

WORKDIR /build

# Cache deps first
COPY trust/go.mod trust/
COPY auth/go.mod auth/
COPY chain/go.mod chain/

RUN cd trust && go mod download && \
    cd ../auth && go mod download && \
    cd ../chain && go mod download

# Copy source
COPY trust/ trust/
COPY auth/ auth/
COPY chain/ chain/

# Build and test all three modules
RUN cd trust && go build ./... && go vet ./... && go test -race ./... && \
    cd ../auth && go build ./... && go vet ./... && go test -race ./... && \
    cd ../chain && go build ./... && go vet ./... && go test -race ./...

# govulncheck
RUN go install golang.org/x/vuln/cmd/govulncheck@latest && \
    cd trust && govulncheck ./... && \
    cd ../auth && govulncheck ./... && \
    cd ../chain && govulncheck ./...

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/ /opt/trust/

LABEL org.opencontainers.image.title="trust"
LABEL org.opencontainers.image.description="Go auth and crypto platform — build and test image"
LABEL org.opencontainers.image.source="https://github.com/bperin/trust"
LABEL org.opencontainers.image.license="MIT"

# This image is for CI/testing. It contains the source tree after
# successful build + test + vulncheck. No binary to run — the modules
# are libraries, not executables.
CMD ["echo", "trust build image — all modules built and tested successfully"]
