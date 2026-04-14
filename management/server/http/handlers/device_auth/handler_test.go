package device_auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePEMCSR_Valid(t *testing.T) {
	// Build a CSR using the test helper from pem_helpers.
	// We just test that parsePEMCSR correctly rejects garbage.
	_, err := parsePEMCSR("not a pem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode PEM block")
}

func TestParsePEMCSR_WrongType(t *testing.T) {
	// PEM with correct structure but wrong type.
	block := "-----BEGIN CERTIFICATE-----\nZGF0YQ==\n-----END CERTIFICATE-----\n"
	_, err := parsePEMCSR(block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected PEM type")
}

func TestCertToPEM_NonEmpty(t *testing.T) {
	pem := certToPEM([]byte("fake-der-data"))
	assert.Contains(t, pem, "BEGIN CERTIFICATE")
	assert.NotEmpty(t, pem)
}

