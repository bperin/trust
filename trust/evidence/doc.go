// Package evidence defines content-addressed evidence references for the
// trust object model.
//
// An EvidenceRef is a triple of (Type, URI, ContentHash). ContentHash —
// the [FIPS 180-4] SHA-256 digest of the evidence bytes — is the identity
// of the reference. Type is a canonical evidence type tag and URI is an
// advisory retrieval hint: a network location, file path, or content
// identifier that tells a consumer where the bytes might be found. The
// URI is never trusted as identity and is never dereferenced by this
// package.
//
// A dead URI degrades to "unverifiable at that location," not "false":
// VerifyContent takes the content bytes directly, so evidence obtained
// from any other source still verifies against ContentHash. The digest
// comparison uses crypto/subtle.ConstantTimeCompare so verification does
// not leak how many digest bytes matched.
//
// All functions in this package are pure: no I/O, no network fetch, no
// logging, and no mutable state.
//
// Standards referenced:
//   - [FIPS 180-4] — SHA-256
package evidence
