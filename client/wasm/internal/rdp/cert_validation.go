//go:build js

package rdp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"syscall/js"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	certValidationTimeout = 5 * time.Minute
)

func (p *RDCleanPathProxy) validateCertificateWithJS(conn *proxyConnection, certChain [][]byte) (bool, error) {
	if !conn.wsHandlers.Get("onCertificateRequest").Truthy() {
		return false, fmt.Errorf("certificate validation handler not configured")
	}

	certInfo := js.Global().Get("Object").New()
	certInfo.Set("ServerAddr", conn.destination)

	certArray := js.Global().Get("Array").New()
	for i, certBytes := range certChain {
		uint8Array := js.Global().Get("Uint8Array").New(len(certBytes))
		js.CopyBytesToJS(uint8Array, certBytes)
		certArray.SetIndex(i, uint8Array)
	}
	certInfo.Set("ServerCertChain", certArray)
	if len(certChain) > 0 {
		cert, err := x509.ParseCertificate(certChain[0])
		if err == nil {
			info := js.Global().Get("Object").New()
			info.Set("subject", cert.Subject.String())
			info.Set("issuer", cert.Issuer.String())
			info.Set("validFrom", cert.NotBefore.Format(time.RFC3339))
			info.Set("validTo", cert.NotAfter.Format(time.RFC3339))
			info.Set("serialNumber", cert.SerialNumber.String())
			certInfo.Set("CertificateInfo", info)
		}
	}

	promise := conn.wsHandlers.Call("onCertificateRequest", certInfo)

	resultChan := make(chan bool, 1)
	errorChan := make(chan error, 1)

	// Release from inside the callbacks so a post-timeout promise resolution
	// does not invoke an already-released func.
	var thenFn, catchFn js.Func
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			thenFn.Release()
			catchFn.Release()
		})
	}
	thenFn = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer release()
		resultChan <- args[0].Bool()
		return nil
	})
	catchFn = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer release()
		errorChan <- fmt.Errorf("certificate validation failed")
		return nil
	})

	promise.Call("then", thenFn).Call("catch", catchFn)

	select {
	case result := <-resultChan:
		if result {
			log.Info("Certificate accepted by user")
		} else {
			log.Info("Certificate rejected by user")
		}
		return result, nil
	case err := <-errorChan:
		return false, err
	case <-time.After(certValidationTimeout):
		return false, fmt.Errorf("certificate validation timeout")
	}
}

func (p *RDCleanPathProxy) getTLSConfigWithValidation(conn *proxyConnection, requiresCredSSP bool) *tls.Config {
	config := &tls.Config{
		InsecureSkipVerify: true, // We'll validate manually after handshake
		VerifyConnection: func(cs tls.ConnectionState) error {
			var certChain [][]byte
			for _, cert := range cs.PeerCertificates {
				certChain = append(certChain, cert.Raw)
			}

			accepted, err := p.validateCertificateWithJS(conn, certChain)
			if err != nil {
				return err
			}
			if !accepted {
				return fmt.Errorf("certificate rejected by user")
			}

			return nil
		},
	}

	// CredSSP (NLA) requires TLS 1.2 - it's incompatible with TLS 1.3
	if requiresCredSSP {
		config.MinVersion = tls.VersionTLS12
		config.MaxVersion = tls.VersionTLS12
	} else {
		config.MinVersion = tls.VersionTLS12
		config.MaxVersion = tls.VersionTLS13
	}

	return config
}
