//go:build ios || android

package encryption

// maxSharedKeys is small on mobile, where the process runs under a tight memory
// limit. A miss only costs a fresh key derivation. An entry costs about 130 bytes,
// so a full cache is around 130 KB.
const maxSharedKeys = 1 << 10
