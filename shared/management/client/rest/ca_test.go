//go:build integration
// +build integration

package rest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

var (
	testCACert = api.CACertificateResponse{
		Id:          "ca-1",
		Fingerprint: "abc123",
		NotBefore:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:    time.Date(2034, 1, 1, 0, 0, 0, 0, time.UTC),
		IsActive:    true,
		CreatedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	testIssuedCert = api.IssuedCertificateResponse{
		Id:           "cert-1",
		PeerId:       "peer-1",
		SerialNumber: "1234",
		DnsNames:     []string{"peer1.example.com"},
		HasWildcard:  false,
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		SigningType:   "acme",
		Revoked:      false,
		CreatedAt:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}
)

func TestCA_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ca", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal([]api.CACertificateResponse{testCACert})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.CertificateAuthority.ListCAs(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testCACert, ret[0])
	})
}

func TestCA_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ca", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.CertificateAuthority.ListCAs(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestCA_Init_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ca", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			retBytes, _ := json.Marshal(testCACert)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.CertificateAuthority.InitCA(context.Background())
		require.NoError(t, err)
		assert.Equal(t, testCACert, *ret)
	})
}

func TestCA_Init_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ca", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Failed", Code: 500})
			w.WriteHeader(500)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.CertificateAuthority.InitCA(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "Failed", err.Error())
		assert.Nil(t, ret)
	})
}

func TestCA_Get_200(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
	certWithPem := testCACert
	certWithPem.CertificatePem = &pem

	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ca/ca-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal(certWithPem)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.CertificateAuthority.GetCA(context.Background(), "ca-1")
		require.NoError(t, err)
		assert.Equal(t, certWithPem, *ret)
		assert.NotNil(t, ret.CertificatePem)
	})
}

func TestCA_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ca/ca-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.CertificateAuthority.GetCA(context.Background(), "ca-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Nil(t, ret)
	})
}

func TestCA_Deactivate_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ca/ca-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.CertificateAuthority.DeactivateCA(context.Background(), "ca-1")
		require.NoError(t, err)
	})
}

func TestCA_Deactivate_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ca/ca-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.CertificateAuthority.DeactivateCA(context.Background(), "ca-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestCA_Rotate_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ca/rotate", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			retBytes, _ := json.Marshal(testCACert)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.CertificateAuthority.RotateCA(context.Background())
		require.NoError(t, err)
		assert.Equal(t, testCACert, *ret)
	})
}

func TestCA_Rotate_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ca/rotate", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No active CA", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.CertificateAuthority.RotateCA(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No active CA", err.Error())
		assert.Nil(t, ret)
	})
}

func TestCA_ListIssuedCerts_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ca/certificates", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal([]api.IssuedCertificateResponse{testIssuedCert})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.CertificateAuthority.ListIssuedCertificates(context.Background(), "")
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testIssuedCert, ret[0])
	})
}

func TestCA_ListIssuedCerts_WithPeerFilter(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ca/certificates", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "peer-1", r.URL.Query().Get("peer_id"))
			retBytes, _ := json.Marshal([]api.IssuedCertificateResponse{testIssuedCert})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.CertificateAuthority.ListIssuedCertificates(context.Background(), "peer-1")
		require.NoError(t, err)
		assert.Len(t, ret, 1)
	})
}

func TestCA_ListIssuedCerts_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ca/certificates", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Forbidden", Code: 403})
			w.WriteHeader(403)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.CertificateAuthority.ListIssuedCertificates(context.Background(), "")
		assert.Error(t, err)
		assert.Equal(t, "Forbidden", err.Error())
		assert.Empty(t, ret)
	})
}

func TestCA_Revoke_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ca/certificates/1234/revoke", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			w.WriteHeader(200)
		})
		err := c.CertificateAuthority.RevokeCertificate(context.Background(), "1234")
		require.NoError(t, err)
	})
}

func TestCA_Revoke_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ca/certificates/1234/revoke", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.CertificateAuthority.RevokeCertificate(context.Background(), "1234")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}
