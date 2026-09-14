// Package merkle implements [RFC 6962] §2.1 Merkle hash trees with inclusion
// proofs and consistency proofs, hashed with [FIPS 180-4] SHA-256.
//
// Leaves are hashed as SHA-256(0x00 || data) and interior nodes as
// SHA-256(0x01 || left || right). The domain separation between leaf and
// interior nodes provides second preimage resistance per [RFC 6962] §2.1.
// Trees are unbalanced in the RFC style: the shape is uniquely determined by
// the leaf count and no leaf padding is applied. The construction is
// unchanged in [RFC 6962]'s successor, [RFC 9162].
//
// Trees are immutable after New. Resolution of the root, audit paths, and
// consistency proofs never re-hash leaf data, so a Tree is safe for
// concurrent use by multiple goroutines.
package merkle
