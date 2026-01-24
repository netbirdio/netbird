// Package tunnel provides machine tunnel functionality for Windows pre-login VPN.
// This package handles the two-phase bootstrap process:
// Phase 1: Setup-Key authentication (for initial enrollment)
// Phase 2: mTLS authentication (after AD CS certificate enrollment)
package tunnel

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/system"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// infoToProtoMeta converts system.Info to proto.PeerSystemMeta for gRPC requests.
func infoToProtoMeta(info *system.Info) *mgmProto.PeerSystemMeta {
	if info == nil {
		return nil
	}

	addresses := make([]*mgmProto.NetworkAddress, 0, len(info.NetworkAddresses))
	for _, addr := range info.NetworkAddresses {
		addresses = append(addresses, &mgmProto.NetworkAddress{
			NetIP: addr.NetIP.String(),
			Mac:   addr.Mac,
		})
	}

	files := make([]*mgmProto.File, 0, len(info.Files))
	for _, file := range info.Files {
		files = append(files, &mgmProto.File{
			Path:             file.Path,
			Exist:            file.Exist,
			ProcessIsRunning: file.ProcessIsRunning,
		})
	}

	return &mgmProto.PeerSystemMeta{
		Hostname:         info.Hostname,
		GoOS:             info.GoOS,
		OS:               info.OS,
		Core:             info.OSVersion,
		OSVersion:        info.OSVersion,
		Platform:         info.Platform,
		Kernel:           info.Kernel,
		NetbirdVersion:   info.NetbirdVersion,
		UiVersion:        info.UIVersion,
		KernelVersion:    info.KernelVersion,
		NetworkAddresses: addresses,
		SysSerialNumber:  info.SystemSerialNumber,
		SysManufacturer:  info.SystemManufacturer,
		SysProductName:   info.SystemProductName,
		Environment: &mgmProto.Environment{
			Cloud:    info.Environment.Cloud,
			Platform: info.Environment.Platform,
		},
		Files: files,
		Flags: &mgmProto.Flags{
			RosenpassEnabled:              info.RosenpassEnabled,
			RosenpassPermissive:           info.RosenpassPermissive,
			ServerSSHAllowed:              info.ServerSSHAllowed,
			DisableClientRoutes:           info.DisableClientRoutes,
			DisableServerRoutes:           info.DisableServerRoutes,
			DisableDNS:                    info.DisableDNS,
			DisableFirewall:               info.DisableFirewall,
			BlockLANAccess:                info.BlockLANAccess,
			BlockInbound:                  info.BlockInbound,
			LazyConnectionEnabled:         info.LazyConnectionEnabled,
			EnableSSHRoot:                 info.EnableSSHRoot,
			EnableSSHSFTP:                 info.EnableSSHSFTP,
			EnableSSHLocalPortForwarding:  info.EnableSSHLocalPortForwarding,
			EnableSSHRemotePortForwarding: info.EnableSSHRemotePortForwarding,
			DisableSSHAuth:                info.DisableSSHAuth,
		},
	}
}

// AuthMethod indicates which authentication method was used for bootstrap.
type AuthMethod int

const (
	// AuthMethodUnknown indicates no authentication method was determined.
	AuthMethodUnknown AuthMethod = iota
	// AuthMethodSetupKey indicates Setup-Key was used (Phase 1).
	AuthMethodSetupKey
	// AuthMethodMTLS indicates mTLS with machine certificate was used (Phase 2).
	AuthMethodMTLS
)

func (m AuthMethod) String() string {
	switch m {
	case AuthMethodSetupKey:
		return "SetupKey"
	case AuthMethodMTLS:
		return "mTLS"
	default:
		return "Unknown"
	}
}

// BootstrapResult contains the result of the bootstrap process.
type BootstrapResult struct {
	// AuthMethod indicates which authentication was used.
	AuthMethod AuthMethod

	// PeerConfig is the local peer configuration from the server.
	PeerConfig *mgmProto.PeerConfig

	// NetbirdConfig contains STUN/TURN/Relay configuration.
	NetbirdConfig *mgmProto.NetbirdConfig

	// MachineIdentity is present only for mTLS auth (Phase 2).
	MachineIdentity *mgmProto.MachineIdentity

	// AllowedDCRoutes are routes this machine can access (mTLS only).
	AllowedDCRoutes []*mgmProto.Route

	// DNSConfig for DC DNS resolution (mTLS only).
	DNSConfig *mgmProto.DNSConfig
}

// MachineConfig extends the standard Config with machine tunnel specific settings.
type MachineConfig struct {
	// Embed standard config
	*profilemanager.Config

	// MachineCertEnabled indicates whether to use machine certificate authentication.
	MachineCertEnabled bool

	// MachineCertThumbprint is the expected certificate thumbprint (optional validation).
	MachineCertThumbprint string

	// SetupKey for Phase 1 bootstrap (one-time use, should be revoked after Phase 2).
	SetupKey string

	// MTLSPort is the port for mTLS connections (default: 33074).
	MTLSPort int

	// DCRoutes are the Domain Controller network CIDRs to route through the tunnel.
	DCRoutes []string
}

// DefaultMTLSPort is the default port for mTLS machine tunnel connections.
const DefaultMTLSPort = 33074

// Bootstrap initiates the machine tunnel authentication process.
// It automatically selects the appropriate authentication method:
// - If a valid machine certificate is available, uses mTLS (Phase 2)
// - Otherwise, falls back to Setup-Key authentication (Phase 1)
//
// After successful Setup-Key bootstrap, the client should:
// 1. Join the domain (if not already joined)
// 2. Enroll a machine certificate via AD CS
// 3. Update config to enable machine cert (MachineCertEnabled = true)
// 4. Restart the service to switch to mTLS auth
func Bootstrap(ctx context.Context, cfg *MachineConfig) (*BootstrapResult, error) {
	if cfg == nil || cfg.Config == nil {
		return nil, fmt.Errorf("config is required")
	}

	// Check if machine certificate is available and enabled
	if cfg.MachineCertEnabled && hasMachineCert(cfg) {
		log.Info("Machine certificate available, attempting mTLS authentication (Phase 2)")
		result, err := bootstrapWithMTLS(ctx, cfg)
		if err != nil {
			// If mTLS fails and we have a setup key, fall back to Phase 1
			if cfg.SetupKey != "" {
				log.Warnf("mTLS authentication failed: %v, falling back to Setup-Key", err)
				return bootstrapWithSetupKey(ctx, cfg)
			}
			return nil, fmt.Errorf("mTLS authentication failed: %w", err)
		}
		return result, nil
	}

	// No machine cert or not enabled - use Setup-Key (Phase 1)
	if cfg.SetupKey == "" {
		return nil, fmt.Errorf("no machine certificate available and no setup key provided; " +
			"for initial bootstrap, provide a setup key")
	}

	log.Info("No machine certificate, using Setup-Key authentication (Phase 1)")
	return bootstrapWithSetupKey(ctx, cfg)
}

// hasMachineCert checks if a valid machine certificate is configured and loadable.
func hasMachineCert(cfg *MachineConfig) bool {
	if cfg.ClientCertPath == "" || cfg.ClientCertKeyPath == "" {
		log.Debug("Machine cert paths not configured")
		return false
	}

	// Try to load the certificate
	cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientCertKeyPath)
	if err != nil {
		log.Debugf("Failed to load machine certificate: %v", err)
		return false
	}

	// Parse to check validity
	if len(cert.Certificate) == 0 {
		log.Debug("No certificate in loaded key pair")
		return false
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Debugf("Failed to parse machine certificate: %v", err)
		return false
	}

	// Check expiry
	now := time.Now()
	if now.Before(x509Cert.NotBefore) {
		log.Debugf("Machine certificate not yet valid (NotBefore: %v)", x509Cert.NotBefore)
		return false
	}
	if now.After(x509Cert.NotAfter) {
		log.Debugf("Machine certificate expired (NotAfter: %v)", x509Cert.NotAfter)
		return false
	}

	// Check for required SAN DNSName
	if len(x509Cert.DNSNames) == 0 {
		log.Debug("Machine certificate has no SAN DNSNames")
		return false
	}

	// Validate thumbprint if specified
	if cfg.MachineCertThumbprint != "" {
		actualThumbprint := fmt.Sprintf("%x", sha256.Sum256(cert.Certificate[0]))
		if !strings.EqualFold(actualThumbprint, cfg.MachineCertThumbprint) {
			log.Debugf("Machine certificate thumbprint mismatch: expected %s, got %s",
				cfg.MachineCertThumbprint, actualThumbprint)
			return false
		}
	}

	log.Debugf("Machine certificate valid: DNSNames=%v, NotAfter=%v", x509Cert.DNSNames, x509Cert.NotAfter)
	return true
}

// bootstrapWithSetupKey performs Phase 1 bootstrap using a Setup-Key.
// This uses the standard Login/Register RPC (not RegisterMachinePeer).
func bootstrapWithSetupKey(ctx context.Context, cfg *MachineConfig) (*BootstrapResult, error) {
	// Validate setup key format
	if _, err := uuid.Parse(cfg.SetupKey); err != nil {
		return nil, fmt.Errorf("invalid setup key format: %w", err)
	}

	log.Debugf("Connecting to management server %s with Setup-Key", cfg.ManagementURL)

	// Create standard management client (not mTLS)
	mgmClient, err := getMgmClient(ctx, cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to management server: %w", err)
	}
	defer func() {
		if closeErr := mgmClient.Close(); closeErr != nil {
			log.Warnf("Failed to close management client: %v", closeErr)
		}
	}()

	// Get server public key
	serverKey, err := mgmClient.GetServerPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get server public key: %w", err)
	}

	// Generate SSH key for registration
	pubSSHKey, err := ssh.GeneratePublicKey([]byte(cfg.SSHKey))
	if err != nil {
		return nil, fmt.Errorf("failed to generate SSH public key: %w", err)
	}

	// Try to login first (peer might already be registered)
	sysInfo := system.GetInfo(ctx)
	setSystemFlags(sysInfo, cfg.Config)

	loginResp, err := mgmClient.Login(*serverKey, sysInfo, pubSSHKey, cfg.DNSLabels)
	if err == nil {
		// Already registered, login successful
		log.Info("Setup-Key bootstrap: peer already registered, login successful")
		return &BootstrapResult{
			AuthMethod:    AuthMethodSetupKey,
			PeerConfig:    loginResp.PeerConfig,
			NetbirdConfig: loginResp.NetbirdConfig,
		}, nil
	}

	// Check if registration is needed
	if !isRegistrationNeeded(err) {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	// Register new peer with setup key
	log.Debug("Peer not registered, registering with Setup-Key")
	loginResp, err = mgmClient.Register(*serverKey, cfg.SetupKey, "", sysInfo, pubSSHKey, cfg.DNSLabels)
	if err != nil {
		return nil, fmt.Errorf("registration with setup key failed: %w", err)
	}

	log.Info("Setup-Key bootstrap: peer registered successfully")
	return &BootstrapResult{
		AuthMethod:    AuthMethodSetupKey,
		PeerConfig:    loginResp.PeerConfig,
		NetbirdConfig: loginResp.NetbirdConfig,
	}, nil
}

// bootstrapWithMTLS performs Phase 2 bootstrap using mTLS with machine certificate.
// This uses the RegisterMachinePeer RPC which is mTLS-only.
func bootstrapWithMTLS(ctx context.Context, cfg *MachineConfig) (*BootstrapResult, error) {
	// Determine mTLS port
	mtlsPort := cfg.MTLSPort
	if mtlsPort == 0 {
		mtlsPort = DefaultMTLSPort
	}

	// Build mTLS URL
	mtlsURL, err := buildMTLSURL(cfg.ManagementURL, mtlsPort)
	if err != nil {
		return nil, fmt.Errorf("failed to build mTLS URL: %w", err)
	}

	log.Debugf("Connecting to management server %s with mTLS", mtlsURL)

	// Load client certificate
	cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientCertKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load machine certificate: %w", err)
	}

	// Create TLS config with client certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Create gRPC connection with mTLS
	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.DialContext(ctx, mtlsURL,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect with mTLS: %w", err)
	}
	defer conn.Close()

	// Create management service client
	client := mgmProto.NewManagementServiceClient(conn)

	// Generate WireGuard key for this machine tunnel
	wgKey, err := wgtypes.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate WireGuard key: %w", err)
	}

	// Get system info
	sysInfo := system.GetInfo(ctx)
	setSystemFlags(sysInfo, cfg.Config)

	// Build registration request
	// Note: The machine identity is extracted from the mTLS certificate by the server,
	// we don't need to send it explicitly
	req := &mgmProto.MachineRegisterRequest{
		Meta:     infoToProtoMeta(sysInfo),
		WgPubKey: []byte(wgKey.PublicKey().String()),
	}

	// Call RegisterMachinePeer RPC
	resp, err := client.RegisterMachinePeer(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("RegisterMachinePeer failed: %w", err)
	}

	log.Infof("mTLS bootstrap successful: identity=%s", resp.MachineIdentity.DnsName)

	return &BootstrapResult{
		AuthMethod:      AuthMethodMTLS,
		PeerConfig:      resp.PeerConfig,
		NetbirdConfig:   resp.NetbirdConfig,
		MachineIdentity: resp.MachineIdentity,
		AllowedDCRoutes: resp.AllowedDcRoutes,
		DNSConfig:       resp.DnsConfig,
	}, nil
}

// getMgmClient creates a standard management gRPC client.
func getMgmClient(ctx context.Context, config *profilemanager.Config) (*mgm.GrpcClient, error) {
	myPrivateKey, err := wgtypes.ParseKey(config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse WireGuard private key: %w", err)
	}

	tlsEnabled := config.ManagementURL.Scheme == "https"

	client, err := mgm.NewClient(ctx, config.ManagementURL.Host, myPrivateKey, tlsEnabled)
	if err != nil {
		return nil, fmt.Errorf("failed to create management client: %w", err)
	}

	return client, nil
}

// buildMTLSURL constructs the mTLS endpoint URL from the management URL.
func buildMTLSURL(mgmURL *url.URL, mtlsPort int) (string, error) {
	if mgmURL == nil {
		return "", fmt.Errorf("management URL is nil")
	}

	// Extract host without port
	host := mgmURL.Hostname()
	if host == "" {
		return "", fmt.Errorf("empty host in management URL")
	}

	return fmt.Sprintf("%s:%d", host, mtlsPort), nil
}

// setSystemFlags sets the system flags from config.
func setSystemFlags(sysInfo *system.Info, config *profilemanager.Config) {
	sysInfo.SetFlags(
		config.RosenpassEnabled,
		config.RosenpassPermissive,
		config.ServerSSHAllowed,
		config.DisableClientRoutes,
		config.DisableServerRoutes,
		config.DisableDNS,
		config.DisableFirewall,
		config.BlockLANAccess,
		config.BlockInbound,
		config.LazyConnectionEnabled,
		config.EnableSSHRoot,
		config.EnableSSHSFTP,
		config.EnableSSHLocalPortForwarding,
		config.EnableSSHRemotePortForwarding,
		config.DisableSSHAuth,
	)
}

// isRegistrationNeeded checks if the error indicates that peer registration is required.
func isRegistrationNeeded(err error) bool {
	if err == nil {
		return false
	}
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	return s.Code() == codes.PermissionDenied
}
