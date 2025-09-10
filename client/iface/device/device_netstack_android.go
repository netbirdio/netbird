//go:build android

package device

func (t *TunNetstackDevice) Create(routes []string, dns string, searchDomains []string) (WGConfigurer, error) {
	return t.create()
}
