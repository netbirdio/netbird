//go:build !devartifactsign

package installer

const (
	DefaultSigningKeysBaseURL = "https://raw.githubusercontent.com/netbirdio/public-keys/refs/heads/main/artifact-signatures"
)
