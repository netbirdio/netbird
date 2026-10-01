//go:build !android

package device

func (t *TunNetstackDevice) Create() (WGConfigurer, error) {
	return t.create()
}
