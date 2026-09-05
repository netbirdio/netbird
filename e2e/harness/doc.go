//go:build e2e

// Package harness provides a self-contained, OIDC-free way to stand up NetBird
// components in containers for end-to-end tests. It is feature-agnostic: any
// suite can ask for a live management server (with an admin PAT minted through
// the unauthenticated /api/setup bootstrap) and, later, a proxy and client.
//
// The harness compiles each component once in a cached builder container and
// mounts the resulting binary into a slim runtime container, so iterating on a
// branch doesn't pay a full image rebuild per run. Everything is gated behind
// the `e2e` build tag so normal builds and unit tests never pull in
// testcontainers.
package harness
