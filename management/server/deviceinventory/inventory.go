// Package deviceinventory provides an interface for verifying whether a device
// is registered in an approved MDM or inventory system before issuing a
// certificate during TPM attestation enrollment (Enrollment Mode C).
package deviceinventory

import (
	"context"
	"encoding/json"
	"fmt"
)

// maxHTTPResponseBytes caps how much data we read from MDM inventory HTTP responses
// to prevent memory exhaustion from malicious or misbehaving servers.
const maxHTTPResponseBytes = 10 << 20 // 10 MiB

// Inventory checks whether a device identified by its TPM EK serial is allowed
// to receive an automatic device certificate without admin approval.
type Inventory interface {
	// IsRegistered returns (true, nil) if the device with the given EK serial
	// is present in the inventory and is eligible for certificate issuance.
	// Returns (false, nil) if the device is not found.
	// Returns (false, err) on transport or authentication errors.
	IsRegistered(ctx context.Context, ekSerial string) (bool, error)
}

// StaticConfig is the JSON structure for a static allow-list inventory.
// Serials must be in decimal format (as produced by Go's big.Int.String()).
type StaticConfig struct {
	Serials []string `json:"allowed_ek_serials"`
}

// StaticInventory is a simple allow-list of EK serial numbers.
type StaticInventory struct {
	allowed map[string]struct{}
}

// NewStaticInventory parses a JSON config blob and returns a StaticInventory.
func NewStaticInventory(configJSON string) (*StaticInventory, error) {
	var cfg StaticConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, fmt.Errorf("deviceinventory: parse static config: %w", err)
	}
	m := make(map[string]struct{}, len(cfg.Serials))
	for _, serial := range cfg.Serials {
		m[serial] = struct{}{}
	}
	return &StaticInventory{allowed: m}, nil
}

// IsRegistered returns true if ekSerial is in the allow-list.
func (s *StaticInventory) IsRegistered(_ context.Context, ekSerial string) (bool, error) {
	_, ok := s.allowed[ekSerial]
	return ok, nil
}

// ─── Multi-source inventory ────────────────────────────────────────────────────

// MultiSourceConfig is the JSON format stored in DeviceAuthSettings.InventoryConfig.
// Multiple sources may be enabled simultaneously; a device is accepted if any
// enabled source recognises it.
type MultiSourceConfig struct {
	Static *MultiSourceStaticConfig `json:"static,omitempty"`
	Intune *MultiSourceIntuneConfig `json:"intune,omitempty"`
	Jamf   *MultiSourceJamfConfig   `json:"jamf,omitempty"`
}

// MultiSourceStaticConfig holds the static allow-list source configuration.
type MultiSourceStaticConfig struct {
	Enabled bool     `json:"enabled"`
	Peers   []string `json:"peers"`   // WireGuard public keys (for future WG-key matching)
	Serials []string `json:"serials"` // EK serial numbers for TPM attestation
}

// MultiSourceIntuneConfig holds the Microsoft Intune source configuration.
type MultiSourceIntuneConfig struct {
	Enabled           bool   `json:"enabled"`
	TenantID          string `json:"tenant_id"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"`
	RequireCompliance bool   `json:"require_compliance"`
}

// MultiSourceJamfConfig holds the Jamf Pro source configuration.
type MultiSourceJamfConfig struct {
	Enabled           bool   `json:"enabled"`
	JamfURL           string `json:"jamf_url"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"`
	RequireManagement bool   `json:"require_management"`
}

// multiInventory chains multiple Inventory backends with OR semantics.
type multiInventory struct {
	inventories []Inventory
}

// IsRegistered returns true if any sub-inventory recognises the device.
func (m *multiInventory) IsRegistered(ctx context.Context, ekSerial string) (bool, error) {
	for _, inv := range m.inventories {
		ok, err := inv.IsRegistered(ctx, ekSerial)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// NewInventory constructs an Inventory from the given type name and JSON config.
// Supported types: "static" (or empty string, which defaults to static).
// Returns an error for unknown types.
func NewInventory(inventoryType, configJSON string) (Inventory, error) {
	switch inventoryType {
	case "", "static":
		return NewStaticInventory(configJSON)
	default:
		return nil, fmt.Errorf("deviceinventory: unknown inventory type %q", inventoryType)
	}
}

// NewMultiInventory constructs a multi-source Inventory from the JSON config blob.
// Only sources with "enabled": true are consulted at enrollment time.
// Returns an inventory that always rejects when no sources are enabled.
func NewMultiInventory(configJSON string) (Inventory, error) {
	if configJSON == "" {
		return &multiInventory{}, nil
	}

	var cfg MultiSourceConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, fmt.Errorf("deviceinventory: parse multi-source config: %w", err)
	}

	var inventories []Inventory

	if cfg.Static != nil && cfg.Static.Enabled {
		staticCfgJSON, err := json.Marshal(StaticConfig{Serials: cfg.Static.Serials})
		if err != nil {
			return nil, fmt.Errorf("deviceinventory: marshal static config: %w", err)
		}
		inv, err := NewStaticInventory(string(staticCfgJSON))
		if err != nil {
			return nil, err
		}
		inventories = append(inventories, inv)
	}

	if cfg.Intune != nil && cfg.Intune.Enabled {
		intuneCfgJSON, err := json.Marshal(IntuneConfig{
			TenantID:     cfg.Intune.TenantID,
			ClientID:     cfg.Intune.ClientID,
			ClientSecret: cfg.Intune.ClientSecret,
		})
		if err != nil {
			return nil, fmt.Errorf("deviceinventory: marshal intune config: %w", err)
		}
		inv, err := NewIntuneInventory(string(intuneCfgJSON))
		if err != nil {
			return nil, err
		}
		inventories = append(inventories, inv)
	}

	if cfg.Jamf != nil && cfg.Jamf.Enabled {
		jamfCfgJSON, err := json.Marshal(JamfConfig{
			URL:          cfg.Jamf.JamfURL,
			ClientID:     cfg.Jamf.ClientID,
			ClientSecret: cfg.Jamf.ClientSecret,
		})
		if err != nil {
			return nil, fmt.Errorf("deviceinventory: marshal jamf config: %w", err)
		}
		inv, err := NewJamfInventory(string(jamfCfgJSON))
		if err != nil {
			return nil, err
		}
		inventories = append(inventories, inv)
	}

	return &multiInventory{inventories: inventories}, nil
}
