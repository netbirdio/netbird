//go:build android

package device

import "fmt"

func (t *TunNetstackDevice) Create(routes []string, dns string, searchDomains []string) (WGConfigurer, error) {
	return t.create()
}

func (t *TunNetstackDevice) RenewTun(fd int) error {
	// Doesn't make sense in Android for Netstack.
	return fmt.Errorf("this function has not been implemented in Netstack for Android")
}
