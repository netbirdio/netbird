package client

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// SignCertificate sends a CSR to the management server for signing.
func (c *GrpcClient) SignCertificate(ctx context.Context, csrDER []byte, signingType proto.CertSigningType, wildcard bool) (*proto.SignCertificateResponse, error) {
	serverPubKey, err := c.GetServerPublicKey()
	if err != nil {
		return nil, err
	}

	req := &proto.SignCertificateRequest{
		CsrDer:      csrDER,
		SigningType:  signingType,
		Wildcard:     wildcard,
	}

	encReq, err := encryption.EncryptMessage(*serverPubKey, c.key, req)
	if err != nil {
		return nil, fmt.Errorf("encrypt sign certificate request: %w", err)
	}

	mgmCtx, cancel := context.WithTimeout(ctx, ConnectTimeout)
	defer cancel()

	resp, err := c.realClient.SignCertificate(mgmCtx, &proto.EncryptedMessage{
		WgPubKey: c.key.PublicKey().String(),
		Body:     encReq,
	})
	if err != nil {
		return nil, err
	}

	signResp := &proto.SignCertificateResponse{}
	if err := encryption.DecryptMessage(*serverPubKey, c.key, resp.Body, signResp); err != nil {
		return nil, fmt.Errorf("decrypt sign certificate response: %w", err)
	}

	return signResp, nil
}

// GetCACertificates fetches the active CA certificates from the management server.
func (c *GrpcClient) GetCACertificates(ctx context.Context) (*proto.GetCACertificatesResponse, error) {
	serverPubKey, err := c.GetServerPublicKey()
	if err != nil {
		return nil, err
	}

	req := &proto.GetCACertificatesRequest{}

	encReq, err := encryption.EncryptMessage(*serverPubKey, c.key, req)
	if err != nil {
		return nil, fmt.Errorf("encrypt get CA certificates request: %w", err)
	}

	mgmCtx, cancel := context.WithTimeout(ctx, ConnectTimeout)
	defer cancel()

	resp, err := c.realClient.GetCACertificates(mgmCtx, &proto.EncryptedMessage{
		WgPubKey: c.key.PublicKey().String(),
		Body:     encReq,
	})
	if err != nil {
		return nil, err
	}

	caResp := &proto.GetCACertificatesResponse{}
	if err := encryption.DecryptMessage(*serverPubKey, c.key, resp.Body, caResp); err != nil {
		return nil, fmt.Errorf("decrypt get CA certificates response: %w", err)
	}

	return caResp, nil
}
