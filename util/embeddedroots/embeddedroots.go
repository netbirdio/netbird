package embeddedroots

import (
	"crypto/x509"
	_ "embed"
	"sync"
)

func Get() *x509.CertPool {
	rootsVar.load()
	return rootsVar.p
}

type roots struct {
	once sync.Once
	p    *x509.CertPool
}

var rootsVar roots

func (r *roots) load() {
	r.once.Do(func() {
		p := x509.NewCertPool()
		p.AppendCertsFromPEM([]byte(isrgRootX1RootPEM))
		p.AppendCertsFromPEM([]byte(isrgRootX2RootPEM))
		r.p = p
	})
}

// Subject: O = Internet Security Research Group, CN = ISRG Root X1
// Key type: RSA 4096
// Validity: until 2030-06-04 (generated 2015-06-04)
//
//go:embed isrg-root-x1.pem
var isrgRootX1RootPEM string

// Subject: O = Internet Security Research Group, CN = ISRG Root X2
// Key type: ECDSA P-384
// Validity: until 2035-09-04 (generated 2020-09-04)
//
//go:embed isrg-root-x2.pem
var isrgRootX2RootPEM string
