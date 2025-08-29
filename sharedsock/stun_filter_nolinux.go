//go:build !linux

package sharedsock

// NewIncomingSTUNFilter is a noop method just because we do not support BPF filters on other platforms than Linux
func NewIncomingSTUNFilter() BPFFilter {
	return nil
}
