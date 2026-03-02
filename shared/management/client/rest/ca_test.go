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

func TestCA_Integration(t *testing.T) {
	withBlackBoxServer(t, func(c *rest.Client) {
		ctx := context.Background()

		// Step 1: Set DNS domain on the account (required for CA init/rotate)
		accounts, err := c.Accounts.List(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, accounts)
		accountID := accounts[0].Id

		_, err = c.Accounts.Update(ctx, accountID, api.AccountRequest{
			Settings: api.AccountSettings{
				DnsDomain:                  ptr("test.netbird.io"),
				PeerLoginExpiration:        accounts[0].Settings.PeerLoginExpiration,
				PeerLoginExpirationEnabled: accounts[0].Settings.PeerLoginExpirationEnabled,
			},
		})
		require.NoError(t, err)

		// Step 2: List CAs (should be empty initially)
		cas, err := c.CertificateAuthority.ListCAs(ctx)
		require.NoError(t, err)
		assert.Len(t, cas, 0)

		// Step 3: Init CA
		initCA, err := c.CertificateAuthority.InitCA(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, initCA.Id)
		assert.NotEmpty(t, initCA.Fingerprint)
		assert.True(t, initCA.IsActive)
		assert.Nil(t, initCA.CertificatePem) // list/init responses don't include PEM

		// Step 4: List CAs (should have 1)
		cas, err = c.CertificateAuthority.ListCAs(ctx)
		require.NoError(t, err)
		assert.Len(t, cas, 1)
		assert.Equal(t, initCA.Id, cas[0].Id)

		// Step 5: Get CA detail (includes PEM)
		detail, err := c.CertificateAuthority.GetCA(ctx, initCA.Id)
		require.NoError(t, err)
		assert.Equal(t, initCA.Id, detail.Id)
		assert.NotNil(t, detail.CertificatePem)
		assert.Contains(t, *detail.CertificatePem, "BEGIN CERTIFICATE")

		// Step 6: Rotate CA (creates new CA, old remains active for trust continuity)
		rotatedCA, err := c.CertificateAuthority.RotateCA(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, rotatedCA.Id)
		assert.NotEqual(t, initCA.Id, rotatedCA.Id)
		assert.True(t, rotatedCA.IsActive)

		// Step 7: List CAs after rotation (both old and new are active)
		cas, err = c.CertificateAuthority.ListCAs(ctx)
		require.NoError(t, err)
		assert.Len(t, cas, 2)

		// Step 8: Deactivate both CAs
		err = c.CertificateAuthority.DeactivateCA(ctx, initCA.Id)
		require.NoError(t, err)
		err = c.CertificateAuthority.DeactivateCA(ctx, rotatedCA.Id)
		require.NoError(t, err)

		// Step 9: List CAs (should be empty now)
		cas, err = c.CertificateAuthority.ListCAs(ctx)
		require.NoError(t, err)
		assert.Len(t, cas, 0)

		// Step 10: List issued certificates (empty, no certs issued via REST)
		certs, err := c.CertificateAuthority.ListIssuedCertificates(ctx, "")
		require.NoError(t, err)
		assert.Len(t, certs, 0)

		// Step 11: Revoke non-existent cert returns error
		err = c.CertificateAuthority.RevokeCertificate(ctx, "nonexistent-serial")
		assert.Error(t, err)
	})
}
