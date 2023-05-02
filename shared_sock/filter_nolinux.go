//go:build !linux

package shared_sock

// NewSTUNFilter is a noop method just because we do not support BPF filters on other platforms than Linux
func NewSTUNFilter() BPFFilter {
	return nil
}
