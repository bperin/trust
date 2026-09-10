// Package did implements decentralized identifier syntax and the core DID
// document data model from [W3C DID-CORE v1.0].
//
// # Syntax
//
// Parse validates the case-sensitive "did:" scheme, method name, and
// method-specific identifier against [W3C DID-CORE v1.0] §3.1. DID URL path, query,
// and fragment components follow §3.2. Parsing preserves the input spelling and
// stores component substrings without copying them.
//
// # Data model
//
// Document, Method, and Service represent the core properties specified by
// [W3C DID-CORE v1.0] §5. Their JSON tags use the property names defined by the DID
// document data model.
//
// # Resolution
//
// Resolver defines the local method operation boundary described by
// [W3C DID-CORE v1.0] §7. Method-specific packages implement resolution; this core
// package performs no network operations.
package did
