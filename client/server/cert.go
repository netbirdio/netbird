package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/cert"
	"github.com/netbirdio/netbird/client/proto"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// RequestCertificate handles a CLI request to generate a key, create a CSR,
// send it to management for signing, and store the resulting certificate.
func (s *Server) RequestCertificate(ctx context.Context, req *proto.CertificateRequest) (*proto.CertificateResponse, error) {
	s.mutex.Lock()
	if !s.clientRunning {
		s.mutex.Unlock()
		return nil, gstatus.Errorf(codes.FailedPrecondition, "client is not running, run 'netbird up' first")
	}
	connectClient := s.connectClient
	s.mutex.Unlock()

	if connectClient == nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "client not initialized")
	}

	engine := connectClient.Engine()
	if engine == nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "engine not initialized")
	}

	if s.certManager == nil {
		return nil, gstatus.Errorf(codes.Internal, "certificate manager not available")
	}

	fqdn := s.statusRecorder.GetLocalPeerState().FQDN
	if fqdn == "" {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "peer FQDN not available, ensure peer is connected")
	}

	key, err := s.certManager.GenerateKey()
	if err != nil {
		return nil, gstatus.Errorf(codes.Internal, "generate key: %v", err)
	}

	csrDER, err := s.certManager.CreateCSR(key, fqdn, req.Wildcard)
	if err != nil {
		return nil, gstatus.Errorf(codes.Internal, "create CSR: %v", err)
	}

	signingType := daemonSigningTypeToMgmt(req.SigningType)

	mgmClient := engine.GetMgmClient()
	if mgmClient == nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "management client not available")
	}

	signCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	signResp, err := mgmClient.SignCertificate(signCtx, csrDER, signingType, req.Wildcard)
	if err != nil {
		return nil, gstatus.Errorf(codes.Internal, "sign certificate: %v", err)
	}

	// Encode private key to PEM
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, gstatus.Errorf(codes.Internal, "unexpected key type")
	}
	keyDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return nil, gstatus.Errorf(codes.Internal, "marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Select cert and chain based on signing type
	var certPEM, chainPEM []byte
	switch signingType {
	case mgmProto.CertSigningType_CERT_SIGNING_ACME:
		certPEM = signResp.AcmeCertPem
		chainPEM = signResp.AcmeChainPem
	default:
		certPEM = signResp.InternalCertPem
		chainPEM = signResp.InternalChainPem
	}

	if err := s.certManager.StoreCert(certPEM, chainPEM, keyPEM); err != nil {
		return nil, gstatus.Errorf(codes.Internal, "store certificate: %v", err)
	}

	// Parse cert to get DNS names for response
	var dnsNames []string
	var expiresAt int64
	if parsed, err := parsePEMCert(certPEM); err == nil {
		dnsNames = parsed.DNSNames
		expiresAt = parsed.NotAfter.Unix()
	} else if signResp.ExpiresAt > 0 {
		expiresAt = signResp.ExpiresAt
	}

	log.Infof("certificate issued for %s, expires at %s", fqdn, time.Unix(expiresAt, 0).Format(time.RFC3339))

	return &proto.CertificateResponse{
		CertPath: s.certManager.CertPath(),
		KeyPath:  s.certManager.KeyPath(),
		DnsNames: dnsNames,
		ExpiresAt: expiresAt,
	}, nil
}

// GetCertificateStatus returns the current certificate status for this peer.
func (s *Server) GetCertificateStatus(_ context.Context, _ *proto.CertificateStatusRequest) (*proto.CertificateStatusResponse, error) {
	if s.certManager == nil {
		return &proto.CertificateStatusResponse{HasCertificate: false}, nil
	}

	if !s.certManager.HasCert() {
		return &proto.CertificateStatusResponse{HasCertificate: false}, nil
	}

	loaded, err := s.certManager.LoadCert()
	if err != nil {
		return nil, gstatus.Errorf(codes.Internal, "load certificate: %v", err)
	}

	caTrusted := false
	caPath := s.certManager.CAPath()
	if caPEM, err := os.ReadFile(caPath); err == nil && len(caPEM) > 0 {
		caTrusted = cert.IsCATrusted(caPEM)
	}

	return &proto.CertificateStatusResponse{
		HasCertificate: true,
		DnsNames:       loaded.DNSNames,
		ExpiresAt:      loaded.NotAfter.Unix(),
		IssuedAt:       loaded.NotBefore.Unix(),
		Issuer:         loaded.Issuer.CommonName,
		CaTrusted:      caTrusted,
		CertPath:       s.certManager.CertPath(),
		KeyPath:        s.certManager.KeyPath(),
	}, nil
}

// TrustCA installs the account CA certificates into the OS trust store.
func (s *Server) TrustCA(_ context.Context, _ *proto.TrustCARequest) (*proto.TrustCAResponse, error) {
	if s.certManager == nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "certificate manager not available")
	}

	caPath := s.certManager.CAPath()
	caPEMData, err := os.ReadFile(caPath)
	if err != nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "no CA certificates available, ensure peer is synced")
	}

	var fingerprints []string
	rest := caPEMData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		singlePEM := pem.EncodeToMemory(block)
		if err := cert.InstallCA(singlePEM); err != nil {
			return nil, gstatus.Errorf(codes.Internal, "install CA: %v", err)
		}

		fp := sha256.Sum256(block.Bytes)
		fingerprints = append(fingerprints, hex.EncodeToString(fp[:]))
	}

	if len(fingerprints) == 0 {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "no valid CA certificates found")
	}

	log.Infof("installed %d CA certificate(s) into OS trust store", len(fingerprints))

	return &proto.TrustCAResponse{
		Success:        true,
		CaFingerprints: fingerprints,
	}, nil
}

// UntrustCA removes the account CA certificates from the OS trust store.
func (s *Server) UntrustCA(_ context.Context, _ *proto.UntrustCARequest) (*proto.UntrustCAResponse, error) {
	if s.certManager == nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "certificate manager not available")
	}

	caPath := s.certManager.CAPath()
	caPEMData, err := os.ReadFile(caPath)
	if err != nil {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "no CA certificates available")
	}

	rest := caPEMData
	var removed int
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		singlePEM := pem.EncodeToMemory(block)
		if err := cert.UninstallCA(singlePEM); err != nil {
			log.Warnf("failed to remove CA from trust store: %v", err)
			continue
		}
		removed++
	}

	log.Infof("removed %d CA certificate(s) from OS trust store", removed)

	return &proto.UntrustCAResponse{
		Success: true,
	}, nil
}

func daemonSigningTypeToMgmt(t proto.DaemonCertSigningType) mgmProto.CertSigningType {
	switch t {
	case proto.DaemonCertSigningType_DAEMON_CERT_SIGNING_ACME:
		return mgmProto.CertSigningType_CERT_SIGNING_ACME
	default:
		return mgmProto.CertSigningType_CERT_SIGNING_INTERNAL
	}
}

func parsePEMCert(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

