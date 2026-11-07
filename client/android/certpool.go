package android

import (
	"fmt"

	"github.com/netbirdio/netbird/util"
)

// SetAndroidCertificates used to push android CA certificates to the golang code.
func SetAndroidCertificates(pemCerts []byte) error {
	pool := util.GetSystemCertPool()

	if ok := pool.AppendCertsFromPEM(pemCerts); !ok {
		return fmt.Errorf("failed to parse any certificates from android")
	}

	util.SetGlobalCertPool(pool)

	return nil
}
