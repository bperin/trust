// Module consumer is a scratch consumer that verifies the exposed
// trust and chain interfaces are sufficient for an external consumer
// to build against without copying code or using local replaces.
//
// When the trust and chain modules are published, this module resolves
// them via `go get github.com/bperin/trust/trust@latest` and
// `go get github.com/bperin/trust/chain@latest`. During local
// development the root go.work workspace provides the local module
// replacements — this go.mod contains no replace directives.
module consumer

go 1.27.1

require (
	github.com/bperin/trust/chain v0.0.0-00010101000000-000000000000
	github.com/bperin/trust/trust v0.0.0-00010101000000-000000000000
)
