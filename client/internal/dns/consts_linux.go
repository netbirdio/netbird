//go:build !android

package dns

const (
	fileUncleanShutdownResolvConfLocation = "/var/lib/netbird/resolv.conf"
)
