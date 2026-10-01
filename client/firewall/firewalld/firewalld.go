// Package firewalld integrates with the firewalld daemon so NetBird can place
// its wg interface into firewalld's "trusted" zone. This is required because
// firewalld's nftables chains are created with NFT_CHAIN_OWNER on recent
// versions, which returns EPERM to any other process that tries to insert
// rules into them. Trusting the interface makes firewalld itself add the
// accept rules to its own chains instead.
package firewalld

// TrustedZone is the firewalld zone name used for interfaces whose traffic
// should bypass firewalld filtering.
const TrustedZone = "trusted"
