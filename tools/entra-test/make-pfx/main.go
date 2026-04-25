// make-pfx produces a self-signed PFX whose Subject CN is a supplied device
// id. Intended for local Entra-enrolment testing only; in production the PFX
// comes from Intune PKCS / SCEP provisioning.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func main() {
	var (
		deviceID = flag.String("device-id", "", "Entra device id (will be the cert Subject CN). Required.")
		out      = flag.String("out", "device.pfx", "Output PFX path")
		password = flag.String("password", "entra-test", "PFX encryption password")
	)
	flag.Parse()
	if *deviceID == "" {
		fmt.Fprintln(os.Stderr, "error: --device-id is required")
		os.Exit(2)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must("generate key", err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: *deviceID},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must("create cert", err)
	leaf, err := x509.ParseCertificate(der)
	must("parse cert", err)

	pfxBytes, err := pkcs12.Modern.Encode(key, leaf, nil, *password)
	must("encode pfx", err)

	must("write pfx", os.WriteFile(*out, pfxBytes, 0o600))
	fmt.Printf("wrote %s (device id %s, password %q)\n", *out, *deviceID, *password)
}

func must(what string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "make-pfx: %s: %v\n", what, err)
		os.Exit(1)
	}
}
