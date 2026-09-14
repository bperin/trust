#!/usr/bin/env bash
# verify-external-consumption.sh — external-consumption check for the
# published trust monorepo modules (PLAN-007 W5, finding A15).
#
# Proves that a consumer outside this repository can resolve and build
# against all four published modules —
#
#   github.com/bperin/trust/trust
#   github.com/bperin/trust/auth
#   github.com/bperin/trust/chain
#   github.com/bperin/trust/kms
#
# — using only `go get`, with no local replace directives and no
# go.work. This models trakt2-crypto, the primary external consumer of
# the published trust and chain modules.
#
# Usage: scripts/verify-external-consumption.sh [ref]
#
#   ref   Module query applied to each module (default: latest). Use a
#         tag such as v0.5.0 for release verification, or a branch or
#         commit for pre-release verification.
#
# The check fails if any module cannot be resolved through the Go module
# proxy / origin, or if the resulting build list contains a replace
# directive or resolved through an active go.work file.
#
# If the repository is private, set GOPRIVATE/GONOSUMDB (or GOFLAGS and
# netrc/ssh credentials) in the environment before running — the script
# deliberately does not override module-fetch configuration.

set -euo pipefail

ref="${1:-latest}"

modules=(
	github.com/bperin/trust/trust
	github.com/bperin/trust/auth
	github.com/bperin/trust/chain
	github.com/bperin/trust/kms
)

scratch="$(mktemp -d "${TMPDIR:-/tmp}/trust-external-consumer.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

cd "$scratch"

# Hard isolation: GOWORK=off guarantees no workspace file participates
# in resolution — the guarantee is explicit, not incidental to the
# tempdir living outside the repo.
export GOWORK=off
gowork="$(go env GOWORK)"
if [ "$gowork" != "off" ]; then
	echo "FAIL: GOWORK is not off (got: ${gowork})" >&2
	exit 1
fi

go mod init example.com/trakt2-crypto-scratch

# A minimal consumer that builds against the exposed interfaces of all
# four modules — proving the published APIs are usable, not just that
# the modules are resolvable.
cat > main.go <<'EOF'
// Command scratch-consumer is a minimal external consumer of the
// published trust monorepo modules. It exists only to prove that the
// modules resolve and their exported APIs are usable without local
// replace directives or go.work.
package main

import (
	"fmt"

	"github.com/bperin/trust/auth/claims"
	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/chain/rlp"
	"github.com/bperin/trust/kms"
	trusthash "github.com/bperin/trust/trust/crypto/hash"
)

func main() {
	// trust: crypto primitives.
	digest := trusthash.NewSHA256().Sum([]byte("external consumer"))

	// chain: RLP encoding and address parsing.
	_ = rlp.EncodeUint64(1)
	addr, err := ethereum.ParseAddress("0x0000000000000000000000000000000000000000")
	if err != nil {
		panic(err)
	}

	// auth / kms: reference the exported API surface.
	var _ claims.Claims
	var _ kms.RemoteSigner

	fmt.Printf("ok: digest=%x addr=%s\n", digest[:4], addr.Hex())
}
EOF

for m in "${modules[@]}"; do
	echo "go get ${m}@${ref}"
	go get "${m}@${ref}"
done

go mod tidy
go build ./...

# Prove resolution used published modules only: no module in the build
# list may carry a Replace entry (covers go.mod and any workspace-level
# replace — the latter is already excluded by GOWORK=off).
replaced="$(go list -m -json all | grep -c '"Replace"' || true)"
if [ "$replaced" != "0" ]; then
	echo "FAIL: ${replaced} module(s) resolved through a replace directive" >&2
	go list -m -json all | grep -B2 '"Replace"' >&2
	exit 1
fi

echo "resolved modules:"
for m in "${modules[@]}"; do
	go list -m "$m"
done

echo "PASS: all four modules resolved via go get at ref '${ref}' with no replace and no go.work"
