package rdp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"syscall/js"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	certValidationTimeout = 60 * time.Second
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

	resultChan := make(chan bool)
	errorChan := make(chan error)

	promise.Call("then", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		result := args[0].Bool()
		resultChan <- result
		return nil
	})).Call("catch", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		errorChan <- fmt.Errorf("certificate validation failed")
		return nil
	}))

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

func (p *RDCleanPathProxy) getTLSConfigWithValidation(conn *proxyConnection) *tls.Config {
	return &tls.Config{
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
}
