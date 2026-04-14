//go:build ignore

// fetch-tpm-roots downloads and saves manufacturer TPM EK CA certificates.
// Run with: go run scripts/fetch-tpm-roots.go
//
// After running, commit the resulting PEM files in
// management/server/devicepki/tpmroots/certs/
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

type caSource struct {
	name string
	url  string
	file string
}

// Sources: manufacturer PKI pages (verify manually before committing).
var sources = []caSource{
	{
		name: "Infineon RSA EK CA 2023",
		url:  "https://pki.infineon.com/OptigaRsaMfrCA063/OptigaRsaMfrCA063.crt",
		file: "infineon-rsa-ek-ca-063.pem",
	},
	{
		name: "Infineon ECC EK CA 2023",
		url:  "https://pki.infineon.com/OptigaEccMfrCA061/OptigaEccMfrCA061.crt",
		file: "infineon-ecc-ek-ca-061.pem",
	},
	{
		name: "STMicro TPM EK Root CA 2",
		url:  "https://tpm.st.com/st-tpm-ekroot/StMicroElectronics_EK_Root_CA_2.cer",
		file: "stmicro-ek-root-ca-2.pem",
	},
	{
		name: "AMD fTPM EK Root CA",
		url:  "https://ftpm.amd.com/pki/amd-ftpm-ek-root-ca.cer",
		file: "amd-ftpm-ek-root-ca.pem",
	},
}

func main() {
	outDir := filepath.Join("management", "server", "devicepki", "tpmroots", "certs")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}

	for _, src := range sources {
		fmt.Printf("Fetching %s...\n", src.name)
		raw, err := fetchBytes(src.url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s: %v\n", src.name, err)
			continue
		}

		pemData := normaliseToPEM(raw)
		if pemData == nil {
			fmt.Fprintf(os.Stderr, "  SKIP %s: could not parse as cert\n", src.name)
			continue
		}

		outPath := filepath.Join(outDir, src.file)
		if err := os.WriteFile(outPath, pemData, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", src.name, err)
			continue
		}

		h := sha256.Sum256(pemData)
		fmt.Printf("  OK  %s  sha256:%s\n", src.file, hex.EncodeToString(h[:]))
	}
}

func fetchBytes(url string) ([]byte, error) {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// normaliseToPEM converts DER or PEM input to PEM. Returns nil on parse failure.
func normaliseToPEM(raw []byte) []byte {
	if b, _ := pem.Decode(raw); b != nil {
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return nil
		}
		return raw
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
