package rest

import (
	"context"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// CertificateAuthorityAPI APIs for Certificate Authority Management, do not use directly
type CertificateAuthorityAPI struct {
	c *Client
}

// ListCAs list all active CA certificates
func (a *CertificateAuthorityAPI) ListCAs(ctx context.Context) ([]api.CACertificateResponse, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/ca", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.CACertificateResponse](resp)
	return ret, err
}

// InitCA initialize a new certificate authority
func (a *CertificateAuthorityAPI) InitCA(ctx context.Context) (*api.CACertificateResponse, error) {
	resp, err := a.c.NewRequest(ctx, "POST", "/api/ca", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.CACertificateResponse](resp)
	return &ret, err
}

// GetCA get CA certificate detail
func (a *CertificateAuthorityAPI) GetCA(ctx context.Context, caID string) (*api.CACertificateResponse, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/ca/"+caID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.CACertificateResponse](resp)
	return &ret, err
}

// DeactivateCA deactivate a CA certificate
func (a *CertificateAuthorityAPI) DeactivateCA(ctx context.Context, caID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/ca/"+caID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}

// RotateCA rotate the certificate authority
func (a *CertificateAuthorityAPI) RotateCA(ctx context.Context) (*api.CACertificateResponse, error) {
	resp, err := a.c.NewRequest(ctx, "POST", "/api/ca/rotate", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.CACertificateResponse](resp)
	return &ret, err
}

// ListIssuedCertificates list issued certificates, optionally filtered by peer ID
func (a *CertificateAuthorityAPI) ListIssuedCertificates(ctx context.Context, peerID string) ([]api.IssuedCertificateResponse, error) {
	var query map[string]string
	if peerID != "" {
		query = map[string]string{"peer_id": peerID}
	}
	resp, err := a.c.NewRequest(ctx, "GET", "/api/ca/certificates", nil, query)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.IssuedCertificateResponse](resp)
	return ret, err
}

// RevokeCertificate revoke an issued certificate by serial number
func (a *CertificateAuthorityAPI) RevokeCertificate(ctx context.Context, serialNumber string) error {
	resp, err := a.c.NewRequest(ctx, "POST", "/api/ca/certificates/"+serialNumber+"/revoke", nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}
