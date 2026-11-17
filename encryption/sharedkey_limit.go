//go:build !ios && !android

package encryption

// maxSharedKeys bounds the cache so peers that come and go (ephemeral peers get a
// new key on every registration) cannot grow it for the lifetime of the process.
// An entry costs about 130 bytes, so a full cache is around 8 MB.
const maxSharedKeys = 1 << 16
