package instance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	goversion "github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/version"
)

const (
	// Version endpoints
	managementVersionURL = "https://pkgs.netbird.io/releases/latest/version"
	dashboardReleasesURL = "https://api.github.com/repos/netbirdio/dashboard/releases/latest"

	// Cache TTL for version information
	versionCacheTTL = 60 * time.Minute

	// HTTP client timeout
	httpTimeout = 5 * time.Second
)

// VersionInfo contains version information for NetBird components
type VersionInfo struct {
	// CurrentVersion is the running management server version
	CurrentVersion string
	// DashboardVersion is the latest available dashboard version from GitHub
	DashboardVersion string
	// ManagementVersion is the latest available management version from GitHub
	ManagementVersion string
	// ManagementUpdateAvailable indicates if a newer management version is available
	ManagementUpdateAvailable bool
}

// githubRelease represents a GitHub release response
type githubRelease struct {
	TagName string `json:"tag_name"`
}

// Manager handles instance-level operations like initial setup.
type Manager interface {
	// IsSetupRequired checks if instance setup is required.
	// Returns true if embedded IDP is enabled and no accounts exist.
	IsSetupRequired(ctx context.Context) (bool, error)

	// CreateOwnerUser creates the initial owner user in the embedded IDP.
	// This should only be called when IsSetupRequired returns true.
	CreateOwnerUser(ctx context.Context, email, password, name string) (*idp.UserData, error)

	// GetVersionInfo returns version information for NetBird components.
	GetVersionInfo(ctx context.Context) (*VersionInfo, error)
}

// DefaultManager is the default implementation of Manager.
type DefaultManager struct {
	store              store.Store
	embeddedIdpManager *idp.EmbeddedIdPManager

	setupRequired bool
	setupMu       sync.RWMutex

	// Version caching
	httpClient       *http.Client
	versionMu        sync.RWMutex
	cachedVersions   *VersionInfo
	lastVersionFetch time.Time
}

// NewManager creates a new instance manager.
// If idpManager is not an EmbeddedIdPManager, setup-related operations will return appropriate defaults.
func NewManager(ctx context.Context, store store.Store, idpManager idp.Manager) (Manager, error) {
	embeddedIdp, _ := idpManager.(*idp.EmbeddedIdPManager)

	m := &DefaultManager{
		store:              store,
		embeddedIdpManager: embeddedIdp,
		setupRequired:      false,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
	}

	if embeddedIdp != nil {
		err := m.loadSetupRequired(ctx)
		if err != nil {
			return nil, err
		}
	}

	return m, nil
}

func (m *DefaultManager) loadSetupRequired(ctx context.Context) error {
	// Check if there are any accounts in the NetBird store
	numAccounts, err := m.store.GetAccountsCounter(ctx)
	if err != nil {
		return err
	}
	hasAccounts := numAccounts > 0

	// Check if there are any users in the embedded IdP (Dex)
	users, err := m.embeddedIdpManager.GetAllAccounts(ctx)
	if err != nil {
		return err
	}
	hasLocalUsers := len(users) > 0

	m.setupMu.Lock()
	m.setupRequired = !(hasAccounts || hasLocalUsers)
	m.setupMu.Unlock()

	return nil
}

// IsSetupRequired checks if instance setup is required.
// Setup is required when:
// 1. Embedded IDP is enabled
// 2. No accounts exist in the store
func (m *DefaultManager) IsSetupRequired(_ context.Context) (bool, error) {
	if m.embeddedIdpManager == nil {
		return false, nil
	}

	m.setupMu.RLock()
	defer m.setupMu.RUnlock()

	return m.setupRequired, nil
}

// CreateOwnerUser creates the initial owner user in the embedded IDP.
func (m *DefaultManager) CreateOwnerUser(ctx context.Context, email, password, name string) (*idp.UserData, error) {

	if err := m.validateSetupInfo(email, password, name); err != nil {
		return nil, err
	}

	if m.embeddedIdpManager == nil {
		return nil, errors.New("embedded IDP is not enabled")
	}

	m.setupMu.RLock()
	setupRequired := m.setupRequired
	m.setupMu.RUnlock()

	if !setupRequired {
		return nil, status.Errorf(status.PreconditionFailed, "setup already completed")
	}

	userData, err := m.embeddedIdpManager.CreateUserWithPassword(ctx, email, password, name)
	if err != nil {
		return nil, fmt.Errorf("failed to create user in embedded IdP: %w", err)
	}

	m.setupMu.Lock()
	m.setupRequired = false
	m.setupMu.Unlock()

	log.WithContext(ctx).Infof("created owner user %s in embedded IdP", email)

	return userData, nil
}

func (m *DefaultManager) validateSetupInfo(email, password, name string) error {
	if email == "" {
		return status.Errorf(status.InvalidArgument, "email is required")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return status.Errorf(status.InvalidArgument, "invalid email format")
	}
	if name == "" {
		return status.Errorf(status.InvalidArgument, "name is required")
	}
	if password == "" {
		return status.Errorf(status.InvalidArgument, "password is required")
	}
	if len(password) < 8 {
		return status.Errorf(status.InvalidArgument, "password must be at least 8 characters")
	}
	return nil
}

// GetVersionInfo returns version information for NetBird components.
func (m *DefaultManager) GetVersionInfo(ctx context.Context) (*VersionInfo, error) {
	m.versionMu.RLock()
	if m.cachedVersions != nil && time.Since(m.lastVersionFetch) < versionCacheTTL {
		cached := *m.cachedVersions
		m.versionMu.RUnlock()
		return &cached, nil
	}
	m.versionMu.RUnlock()

	return m.fetchVersionInfo(ctx)
}

func (m *DefaultManager) fetchVersionInfo(ctx context.Context) (*VersionInfo, error) {
	m.versionMu.Lock()
	// Double-check after acquiring write lock
	if m.cachedVersions != nil && time.Since(m.lastVersionFetch) < versionCacheTTL {
		cached := *m.cachedVersions
		m.versionMu.Unlock()
		return &cached, nil
	}
	m.versionMu.Unlock()

	info := &VersionInfo{
		CurrentVersion: version.NetbirdVersion(),
	}

	// Fetch management version from pkgs.netbird.io (plain text)
	mgmtVersion, err := m.fetchPlainTextVersion(ctx, managementVersionURL)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to fetch management version: %v", err)
	} else {
		info.ManagementVersion = mgmtVersion
		info.ManagementUpdateAvailable = isNewerVersion(info.CurrentVersion, mgmtVersion)
	}

	// Fetch dashboard version from GitHub
	dashVersion, err := m.fetchGitHubRelease(ctx, dashboardReleasesURL)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to fetch dashboard version from GitHub: %v", err)
	} else {
		info.DashboardVersion = dashVersion
	}

	// Update cache
	m.versionMu.Lock()
	m.cachedVersions = info
	m.lastVersionFetch = time.Now()
	m.versionMu.Unlock()

	return info, nil
}

// isNewerVersion returns true if latestVersion is greater than currentVersion
func isNewerVersion(currentVersion, latestVersion string) bool {
	current, err := goversion.NewVersion(currentVersion)
	if err != nil {
		return false
	}

	latest, err := goversion.NewVersion(latestVersion)
	if err != nil {
		return false
	}

	return latest.GreaterThan(current)
}

func (m *DefaultManager) fetchPlainTextVersion(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", "NetBird-Management/"+version.NetbirdVersion())

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 100))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	return strings.TrimSpace(string(body)), nil
}

func (m *DefaultManager) fetchGitHubRelease(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "NetBird-Management/"+version.NetbirdVersion())

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	// Remove 'v' prefix if present
	tag := release.TagName
	if len(tag) > 0 && tag[0] == 'v' {
		tag = tag[1:]
	}

	return tag, nil
}
