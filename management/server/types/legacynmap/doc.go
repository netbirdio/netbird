// Package legacynmap holds a frozen copy of main's network-map computation,
// used only by the main-vs-branch proto equivalence test. All real content is
// behind the nmapequiv build tag; this file exists so the package is still valid
// for untagged builds and `go test ./...`.
//
// Delete this package once the nmdata refactor is validated.
package legacynmap
