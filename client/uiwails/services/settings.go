//go:build !(linux && 386)

package services

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

// SettingsService exposes config get/set operations to the Wails frontend.
type SettingsService struct {
	grpcClient GRPCClientIface
}

// NewSettingsService creates a new SettingsService.
func NewSettingsService(g GRPCClientIface) *SettingsService {
	return &SettingsService{grpcClient: g}
}

// ConfigInfo is a serializable view of the daemon configuration.
type ConfigInfo struct {
	ManagementURL         string `json:"managementUrl"`
	AdminURL              string `json:"adminUrl"`
	PreSharedKey          string `json:"preSharedKey"`
	InterfaceName         string `json:"interfaceName"`
	WireguardPort         int64  `json:"wireguardPort"`
	DisableAutoConnect    bool   `json:"disableAutoConnect"`
	ServerSSHAllowed      bool   `json:"serverSshAllowed"`
	RosenpassEnabled      bool   `json:"rosenpassEnabled"`
	RosenpassPermissive   bool   `json:"rosenpassPermissive"`
	LazyConnectionEnabled bool   `json:"lazyConnectionEnabled"`
	BlockInbound          bool   `json:"blockInbound"`
	DisableNotifications  bool   `json:"disableNotifications"`
}

// GetConfig retrieves the daemon configuration.
func (s *SettingsService) GetConfig() (*ConfigInfo, error) {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := conn.GetConfig(ctx, &proto.GetConfigRequest{})
	if err != nil {
		return nil, fmt.Errorf("get config rpc: %w", err)
	}

	cfg := &ConfigInfo{
		ManagementURL:         resp.ManagementUrl,
		AdminURL:              resp.AdminURL,
		PreSharedKey:          resp.PreSharedKey,
		InterfaceName:         resp.InterfaceName,
		WireguardPort:         resp.WireguardPort,
		DisableAutoConnect:    resp.DisableAutoConnect,
		ServerSSHAllowed:      resp.ServerSSHAllowed,
		RosenpassEnabled:      resp.RosenpassEnabled,
		LazyConnectionEnabled: resp.LazyConnectionEnabled,
		BlockInbound:          resp.BlockInbound,
		DisableNotifications:  resp.DisableNotifications,
	}

	return cfg, nil
}

// SetConfig pushes configuration changes to the daemon.
func (s *SettingsService) SetConfig(cfg ConfigInfo) error {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The SetConfigRequest uses optional pointer fields for most settings.
	req := &proto.SetConfigRequest{
		ManagementUrl:         cfg.ManagementURL,
		AdminURL:              cfg.AdminURL,
		RosenpassEnabled:      &cfg.RosenpassEnabled,
		InterfaceName:         &cfg.InterfaceName,
		WireguardPort:         &cfg.WireguardPort,
		OptionalPreSharedKey:  &cfg.PreSharedKey,
		DisableAutoConnect:    &cfg.DisableAutoConnect,
		ServerSSHAllowed:      &cfg.ServerSSHAllowed,
		RosenpassPermissive:   &cfg.RosenpassPermissive,
		DisableNotifications:  &cfg.DisableNotifications,
		LazyConnectionEnabled: &cfg.LazyConnectionEnabled,
		BlockInbound:          &cfg.BlockInbound,
	}

	if _, err := conn.SetConfig(ctx, req); err != nil {
		log.Errorf("SetConfig rpc failed: %v", err)
		return fmt.Errorf("set config: %w", err)
	}

	return nil
}

// ToggleSSH toggles the SSH server allowed setting.
func (s *SettingsService) ToggleSSH(enabled bool) error {
	cfg, err := s.GetConfig()
	if err != nil {
		return err
	}
	cfg.ServerSSHAllowed = enabled
	return s.SetConfig(*cfg)
}

// ToggleAutoConnect toggles the auto-connect setting.
func (s *SettingsService) ToggleAutoConnect(enabled bool) error {
	cfg, err := s.GetConfig()
	if err != nil {
		return err
	}
	cfg.DisableAutoConnect = !enabled
	return s.SetConfig(*cfg)
}

// ToggleRosenpass toggles the Rosenpass quantum resistance setting.
func (s *SettingsService) ToggleRosenpass(enabled bool) error {
	cfg, err := s.GetConfig()
	if err != nil {
		return err
	}
	cfg.RosenpassEnabled = enabled
	return s.SetConfig(*cfg)
}

// ToggleLazyConn toggles the lazy connections setting.
func (s *SettingsService) ToggleLazyConn(enabled bool) error {
	cfg, err := s.GetConfig()
	if err != nil {
		return err
	}
	cfg.LazyConnectionEnabled = enabled
	return s.SetConfig(*cfg)
}

// ToggleBlockInbound toggles the block inbound setting.
func (s *SettingsService) ToggleBlockInbound(enabled bool) error {
	cfg, err := s.GetConfig()
	if err != nil {
		return err
	}
	cfg.BlockInbound = enabled
	return s.SetConfig(*cfg)
}

// ToggleNotifications toggles the notifications setting.
func (s *SettingsService) ToggleNotifications(enabled bool) error {
	cfg, err := s.GetConfig()
	if err != nil {
		return err
	}
	cfg.DisableNotifications = !enabled
	return s.SetConfig(*cfg)
}
