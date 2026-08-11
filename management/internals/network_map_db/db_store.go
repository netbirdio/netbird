package networkmapdb

import (
	"context"

	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

type NetworkMapDBStore interface { //nolint:revive // established name across the codebase
	BeginTx(ctx context.Context) (NetworkMapDBStoreConn, error)
}

type NetworkMapDBStoreConn interface { //nolint:revive // established name across the codebase
	GetGroups(ctx context.Context, accountId string) ([]nmdata.Group, map[string]map[string]any, error)
	GetDomains(ctx context.Context, accountId string) ([]Domain, error)
	GetPeers(ctx context.Context, accountId string) ([]nmdata.Peer, map[string][]*nmdata.Peer, error)
	GetPolicies(ctx context.Context, accountId string) ([]nmdata.Policy, map[string]map[string]any, map[string]map[string]any, error)
	GetRoutes(ctx context.Context, accountId string) ([]nmdata.Route, error)
	GetNameServerGroups(ctx context.Context, accountId string) ([]nmdata.NameServerGroup, error)
	GetNetworkResources(ctx context.Context, accountId string) ([]nmdata.NetworkResource, error)
	GetNetworkRouters(ctx context.Context, accountId string) (map[string]map[string]*nmdata.NetworkRouter, error)
	GetNetwork(ctx context.Context, accountId string) (nmdata.Network, error)
	GetAppliedZoneCandidates(ctx context.Context, accountId string) ([]networkmap.AppliedZoneCandidate, error)
	GetAccountSettings(ctx context.Context, accountId string) (nmdata.AccountSettingsInfo, error)
	GetPostureChecks(ctx context.Context, accountId string) ([]nmdata.PostureChecks, map[string]string, error)
	GetAllowedUsers(ctx context.Context, accountId string) (map[string]struct{}, map[string][]string, error)
	GetDnsSettings(ctx context.Context, accountId string) (nmdata.DNSSettings, error)
	GetNetworkXIDToPublicIdMap(ctx context.Context, accountId string) (map[string]string, error)
	GetPrivateServices(ctx context.Context, accountId string) ([]Service, error)
	GetProxyTargetedDomainResourceIDs(ctx context.Context, accountId string) (map[string]struct{}, error)

	CommitTx(ctx context.Context) error
	RollbackTx(ctx context.Context) error
}

type NetworkMapDBStoreImpl struct { //nolint:revive // established name across the codebase
	store                   NetworkMapDBStore
	integratedPeerValidator integrated_validator.IntegratedValidator
	extraSettingsManager    settings.Manager
}

func NewNetworkMapDBStoreImpl(store NetworkMapDBStore, integratedPeerValidator integrated_validator.IntegratedValidator, extraSettingsManager settings.Manager) *NetworkMapDBStoreImpl {
	return &NetworkMapDBStoreImpl{
		store:                   store,
		integratedPeerValidator: integratedPeerValidator,
		extraSettingsManager:    extraSettingsManager,
	}
}
