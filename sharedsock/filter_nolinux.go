//go:build !linux

package sharedsock

// NewSTUNFilter is a noop method just because we do not support BPF filters on other platforms than Linux
func NewSTUNFilter() BPFFilter {
	return nil
}
