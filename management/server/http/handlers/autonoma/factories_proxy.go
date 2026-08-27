package autonoma

import (
	"context"
	"fmt"
	"net"
	"time"

	sdk "github.com/autonoma-ai/sdk/sdks/go/autonoma"
	"github.com/google/uuid"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// ProxyInput registers a reverse-proxy node against the account, the way a
// self-hosted proxy does when it connects over gRPC. Nothing else in the proxy
// surface works without one: domains are only accepted for a cluster that has a
// live proxy behind it, and a service derives its cluster from its domain.
type ProxyInput struct {
	// AccountID scopes the cluster to this account (a "bring your own proxy"
	// cluster). Its address only has to be unique among the account's own.
	AccountID string `json:"accountId"`
	// ClusterAddress is the hostname the cluster serves; service domains are
	// subdomains of it or custom domains pointed at it.
	ClusterAddress string `json:"clusterAddress"`
	IPAddress      string `json:"ipAddress,omitempty"`
	// HeartbeatValidForMinutes is an offset, and it is load-bearing: a proxy
	// counts as active only while its last heartbeat is under two minutes old,
	// and a seeded proxy has no process behind it to keep sending one. The
	// heartbeat is therefore stamped this far ahead, which keeps the cluster
	// online for the length of a test run instead of for two minutes.
	HeartbeatValidForMinutes int `json:"heartbeatValidForMinutes,omitempty"`
	// SupportsCustomPorts lets services on this cluster bind their own ports.
	SupportsCustomPorts bool `json:"supportsCustomPorts,omitempty"`
	// GatewayID names an agent-network gateway this cluster serves, for a
	// recipe whose ClusterAddress is that gateway's endpoint. It changes
	// nothing about the cluster - the two are linked by the hostname alone -
	// and exists for ordering: the product refuses to delete a gateway while a
	// proxy is serving its endpoint, so the proxy has to be created after the
	// gateway and torn down before it. Referencing it is what the SDK derives
	// that order from.
	GatewayID string `json:"gatewayId,omitempty"`
}

func (f *factories) proxyFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *ProxyInput, _ sdk.FactoryContext) (map[string]any, error) {
			proxyID := "proxy-" + uuid.NewString()
			sessionID := uuid.NewString()
			accountID := in.AccountID
			supportsCustomPorts := in.SupportsCustomPorts
			requireSubdomain := false

			connected, err := f.deps.ProxyManager.Connect(ctx, proxyID, sessionID, in.ClusterAddress,
				orDefaultStr(in.IPAddress, "203.0.113.10"), &accountID, &proxy.Capabilities{
					SupportsCustomPorts: &supportsCustomPorts,
					RequireSubdomain:    &requireSubdomain,
				})
			if err != nil {
				return nil, fmt.Errorf("register proxy on cluster %q: %w", in.ClusterAddress, err)
			}

			connected.LastSeen = minutesFromNow(orDefaultInt(in.HeartbeatValidForMinutes, 120))
			if err := f.deps.Store.SaveProxy(ctx, connected); err != nil {
				return nil, fmt.Errorf("extend the heartbeat of proxy %q: %w", proxyID, err)
			}

			return map[string]any{
				"id":             proxyID,
				"accountId":      in.AccountID,
				"sessionId":      sessionID,
				"clusterAddress": in.ClusterAddress,
			}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			return f.cleaner.DeleteProxyForTestData(ctx, str(record, "id"), str(record, "sessionId"))
		},
	)
}

// DomainInput registers a custom domain against one of the account's proxy
// clusters. The domain column is unique across every account, so a recipe must
// make it per-run.
type DomainInput struct {
	AccountID string `json:"accountId"`
	Domain    string `json:"domain"`
	// ProxyID names the proxy whose cluster serves this domain. Referencing the
	// proxy rather than repeating its address is also what orders the two: a
	// domain is only accepted for a cluster that already has a live proxy.
	ProxyID string `json:"proxyId,omitempty"`
	// TargetCluster is an explicit cluster address, for a cluster this run did
	// not seed. Use it instead of ProxyID, not alongside it.
	TargetCluster string `json:"targetCluster,omitempty"`
}

func (f *factories) domainFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *DomainInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			cluster := in.TargetCluster
			if in.ProxyID != "" {
				cluster, err = lookupRef(fctx, "Proxy", in.ProxyID, "clusterAddress")
				if err != nil {
					return nil, err
				}
			}
			if cluster == "" {
				return nil, fmt.Errorf("domain %q needs a proxyId or a targetCluster", in.Domain)
			}

			created, err := f.deps.DomainManager.CreateDomain(ctx, in.AccountID, actor, in.Domain, cluster)
			if err != nil {
				return nil, fmt.Errorf("register domain %q: %w", in.Domain, err)
			}

			return map[string]any{"id": created.ID, "accountId": in.AccountID, "domain": in.Domain}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.DomainManager.DeleteDomain(ctx, accountID, owner, str(record, "id"))
		},
	)
}

// ServiceTargetInput is one upstream behind a service. A target names something
// the account already has - a peer or a network resource - rather than a bare
// address: the product resolves the host from that reference at read time and
// refuses a target it cannot find. Targets are written with their service in
// the same transaction, so they have no factory of their own.
type ServiceTargetInput struct {
	// PeerID sends traffic to a peer's overlay address; ResourceID sends it to
	// a network resource. Exactly one of the two.
	PeerID     string `json:"peerId,omitempty"`
	ResourceID string `json:"resourceId,omitempty"`
	Port       int    `json:"port"`
	// Protocol is "http" or "https".
	Protocol string `json:"protocol,omitempty"`
	Path     string `json:"path,omitempty"`
}

// ServiceInput publishes an internal service on a proxied domain. The domain is
// unique across every account, so a recipe must make it per-run.
type ServiceInput struct {
	AccountID string `json:"accountId"`
	Name      string `json:"name"`
	// DomainID names the registered domain the service is published on.
	// Referencing it is what orders the two, since the product derives the
	// service's proxy cluster from a domain that already exists.
	DomainID string `json:"domainId,omitempty"`
	// Domain is an explicit hostname, for a subdomain of a cluster's own
	// address. Use it instead of DomainID, not alongside it.
	Domain   string               `json:"domain,omitempty"`
	Targets  []ServiceTargetInput `json:"targets"`
	Disabled bool                 `json:"disabled,omitempty"`
	// PasswordAuth, when set, gates the service behind this shared password.
	// It is hashed on the way in, exactly as the API hashes it.
	PasswordAuth string `json:"passwordAuth,omitempty"`
	// PinAuth is a six-digit code, an alternative to the password gate.
	PinAuth string `json:"pinAuth,omitempty"`
	// SSOGroups gates the service behind SSO, restricted to these groups.
	SSOGroups []string `json:"ssoGroups,omitempty"`
}

func (f *factories) serviceFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *ServiceInput, fctx sdk.FactoryContext) (map[string]any, error) {
			actor, err := f.actorFor(ctx, fctx, in.AccountID)
			if err != nil {
				return nil, err
			}

			domainName := in.Domain
			if in.DomainID != "" {
				domainName, err = lookupRef(fctx, "Domain", in.DomainID, "domain")
				if err != nil {
					return nil, err
				}
			}
			if domainName == "" {
				return nil, fmt.Errorf("service %q needs a domainId or a domain", in.Name)
			}

			targets := make([]*service.Target, 0, len(in.Targets))
			for _, target := range in.Targets {
				t := &service.Target{
					AccountID: in.AccountID,
					Port:      uint16(target.Port),
					Protocol:  orDefaultStr(target.Protocol, "http"),
					Enabled:   true,
				}
				switch {
				case target.PeerID != "":
					t.TargetType = service.TargetTypePeer
					t.TargetId = target.PeerID
				case target.ResourceID != "":
					t.TargetType = service.TargetTypeHost
					t.TargetId = target.ResourceID
				default:
					return nil, fmt.Errorf("service %q: every target needs a peerId or a resourceId", in.Name)
				}
				if target.Path != "" {
					path := target.Path
					t.Path = &path
				}
				targets = append(targets, t)
			}

			svc := &service.Service{
				AccountID:      in.AccountID,
				Name:           in.Name,
				Domain:         domainName,
				Targets:        targets,
				Enabled:        !in.Disabled,
				PassHostHeader: true,
				Mode:           "http",
			}
			if in.PasswordAuth != "" {
				svc.Auth.PasswordAuth = &service.PasswordAuthConfig{Enabled: true, Password: in.PasswordAuth}
			}
			if in.PinAuth != "" {
				svc.Auth.PinAuth = &service.PINAuthConfig{Enabled: true, Pin: in.PinAuth}
			}
			if len(in.SSOGroups) > 0 {
				svc.Auth.BearerAuth = &service.BearerAuthConfig{Enabled: true, DistributionGroups: in.SSOGroups}
			}

			created, err := f.deps.ServiceManager.CreateService(ctx, in.AccountID, actor, svc)
			if err != nil {
				return nil, fmt.Errorf("publish service %q on %q: %w", in.Name, domainName, err)
			}

			return map[string]any{
				"id":        created.ID,
				"accountId": in.AccountID,
				"name":      in.Name,
				"domain":    domainName,
			}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			accountID := str(record, "accountId")
			owner, err := f.deps.Store.GetAccountCreatedBy(ctx, store.LockingStrengthNone, accountID)
			if err != nil {
				return ignoreNotFound(err)
			}
			return f.deps.ServiceManager.DeleteService(ctx, accountID, owner, str(record, "id"))
		},
	)
}

// ProxyAccessTokenInput mints a token a self-hosted proxy authenticates with.
//
// The API creates these inline in its request handler rather than through a
// manager, so the factory makes the same two calls the handler makes - mint,
// then save - without the request parsing and permission check around them.
type ProxyAccessTokenInput struct {
	AccountID string `json:"accountId"`
	Name      string `json:"name"`
	// CreatedBy is the user id the token is attributed to; empty means the
	// account owner.
	CreatedBy string `json:"createdBy,omitempty"`
	// ExpiresInHours is an offset from seeding time, because the product
	// rejects a token whose expiry has passed. 0 means it never expires.
	ExpiresInHours int `json:"expiresInHours,omitempty"`
}

func (f *factories) proxyAccessTokenFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *ProxyAccessTokenInput, fctx sdk.FactoryContext) (map[string]any, error) {
			createdBy := in.CreatedBy
			if createdBy == "" {
				owner, err := f.actorFor(ctx, fctx, in.AccountID)
				if err != nil {
					return nil, err
				}
				createdBy = owner
			}

			accountID := in.AccountID
			generated, err := types.CreateNewProxyAccessToken(in.Name,
				time.Duration(orDefaultInt(in.ExpiresInHours, 24*30))*time.Hour, &accountID, createdBy)
			if err != nil {
				return nil, fmt.Errorf("mint the proxy access token %q: %w", in.Name, err)
			}
			if err := f.deps.Store.SaveProxyAccessToken(ctx, &generated.ProxyAccessToken); err != nil {
				return nil, fmt.Errorf("save the proxy access token %q: %w", in.Name, err)
			}

			return map[string]any{
				"id":        generated.ID,
				"accountId": in.AccountID,
				"name":      in.Name,
				"token":     string(generated.PlainToken),
			}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			return f.cleaner.DeleteProxyAccessTokenForTestData(ctx, str(record, "accountId"), str(record, "id"))
		},
	)
}

// AccessLogEntryInput seeds one request through the reverse proxy.
//
// With AgentNetwork set the same entry is flattened into the agent-network
// ledger on the way in, which is what produces the usage rows (and, when the
// account has agent-network log collection bootstrapped, the agent-network
// access-log rows and their authorising-group children).
type AccessLogEntryInput struct {
	AccountID string `json:"accountId"`
	ServiceID string `json:"serviceId"`
	UserID    string `json:"userId,omitempty"`
	Method    string `json:"method,omitempty"`
	// GatewayID names the agent-network gateway the request went through, and
	// supplies the host. Referencing it is also what orders the two: the
	// agent-network trail is only written for an account whose gateway is
	// already bootstrapped with log collection on.
	GatewayID string `json:"gatewayId,omitempty"`
	// Host is an explicit hostname, for a request that did not go through the
	// gateway. Use it instead of GatewayID, not alongside it.
	Host string `json:"host,omitempty"`
	Path string `json:"path,omitempty"`
	// MinutesAgo places the request before now. The access-log screen filters
	// and orders by time and a retention sweep drops old rows, so this has to
	// be an offset rather than a date.
	MinutesAgo     int    `json:"minutesAgo,omitempty"`
	StatusCode     int    `json:"statusCode,omitempty"`
	DurationMs     int    `json:"durationMs,omitempty"`
	SourceIP       string `json:"sourceIp,omitempty"`
	AuthMethodUsed string `json:"authMethodUsed,omitempty"`
	BytesUpload    int64  `json:"bytesUpload,omitempty"`
	BytesDownload  int64  `json:"bytesDownload,omitempty"`
	// Protocol is "http", "tcp" or "udp".
	Protocol string `json:"protocol,omitempty"`
	// AgentNetwork routes the entry through the LLM-gateway ledger.
	AgentNetwork bool `json:"agentNetwork,omitempty"`
	// Metadata carries the agent-network dimensions the proxy stamps, such as
	// llm.provider, llm.model, llm.session_id and the token counters.
	Metadata map[string]string `json:"metadata,omitempty"`
}

func (f *factories) accessLogFactory() sdk.FactoryDefinition {
	return define(f,
		func(ctx context.Context, in *AccessLogEntryInput, fctx sdk.FactoryContext) (map[string]any, error) {
			host := in.Host
			if in.GatewayID != "" {
				resolved, err := lookupRef(fctx, "AgentNetworkSettings", in.GatewayID, "domain")
				if err != nil {
					return nil, err
				}
				host = resolved
			}
			if host == "" {
				return nil, fmt.Errorf("access log entry needs a gatewayId or a host")
			}

			entry := &accesslogs.AccessLogEntry{
				ID:             uuid.NewString(),
				AccountID:      in.AccountID,
				ServiceID:      in.ServiceID,
				Timestamp:      minutesAgo(in.MinutesAgo),
				Method:         orDefaultStr(in.Method, "GET"),
				Host:           host,
				Path:           orDefaultStr(in.Path, "/"),
				Duration:       time.Duration(orDefaultInt(in.DurationMs, 120)) * time.Millisecond,
				StatusCode:     orDefaultInt(in.StatusCode, 200),
				UserId:         in.UserID,
				AuthMethodUsed: in.AuthMethodUsed,
				BytesUpload:    in.BytesUpload,
				BytesDownload:  in.BytesDownload,
				Protocol:       accesslogs.AccessLogProtocol(orDefaultStr(in.Protocol, string(accesslogs.AccessLogProtocolHTTP))),
				Metadata:       in.Metadata,
				AgentNetwork:   in.AgentNetwork,
			}
			if in.SourceIP != "" {
				ip := net.ParseIP(in.SourceIP)
				if ip == nil {
					return nil, fmt.Errorf("sourceIp %q is not an IP address", in.SourceIP)
				}
				entry.GeoLocation = nbpeer.Location{ConnectionIP: ip}
			}

			if err := f.deps.AccessLogsManager.SaveAccessLog(ctx, entry); err != nil {
				return nil, fmt.Errorf("save the access log for %s %s: %w", entry.Method, entry.Path, err)
			}

			return map[string]any{
				"id":        entry.ID,
				"accountId": in.AccountID,
				"serviceId": in.ServiceID,
			}, nil
		},
		func(ctx context.Context, record map[string]any) error {
			return f.cleaner.DeleteAccessLogForTestData(ctx, str(record, "accountId"), str(record, "id"))
		},
	)
}
