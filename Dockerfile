FROM golang:1.27-bookworm AS builder

WORKDIR /build

# Cache deps first
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build and test
RUN go build ./... && go vet ./... && go test -race ./...

# govulncheck
RUN go install golang.org/x/vuln/cmd/govulncheck@latest && \
    govulncheck ./...

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/ /opt/trust/

LABEL org.opencontainers.image.title="trust"
LABEL org.opencontainers.image.description="Go auth and crypto platform — build and test image"
LABEL org.opencontainers.image.source="https://github.com/bperin/trust"
LABEL org.opencontainers.image.license="MIT"

# This image is for CI/testing. It contains the source tree after
# successful build + test + vulncheck. No binary to run — the module
# is a library, not an executable.
CMD ["echo", "trust build image — built and tested successfully"]
