//go:build !linux || android

package wgproxy

func NewFactory(wgPort int) *Factory {
	return &Factory{wgPort: wgPort}
}
