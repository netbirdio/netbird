package server

import (
	"context"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/management-integrations/integrations"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain/manager"
	nbreverseproxy "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/manager"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	zonesManager "github.com/netbirdio/netbird/management/internals/modules/zones/manager"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	recordsManager "github.com/netbirdio/netbird/management/internals/modules/zones/records/manager"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/networks"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/routers"

	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/users"
)

const (
	geolocationDisabledKey = "NB_DISABLE_GEOLOCATION"
)

func (s *BaseServer) GeoLocationManager() geolocation.Geolocation {
	if os.Getenv(geolocationDisabledKey) == "true" {
		log.Info("geolocation service is disabled, skipping initialization")
		return nil
	}

	return Create(s, func() geolocation.Geolocation {
		geo, err := geolocation.NewGeolocation(context.Background(), s.Config.Datadir, !s.disableGeoliteUpdate)
		if err != nil {
			log.Fatalf("could not initialize geolocation service: %v", err)
		}

		log.Infof("geolocation service has been initialized from %s", s.Config.Datadir)

		return geo
	})
}

func (s *BaseServer) PermissionsManager() permissions.Manager {
	return Create(s, func() permissions.Manager {
		manager := integrations.InitPermissionsManager(s.Store(), s.Metrics().GetMeter())

		s.AfterInit(func(s *BaseServer) {
			manager.SetAccountManager(s.AccountManager())
		})

		return manager
	})
}

func (s *BaseServer) UsersManager() users.Manager {
	return Create(s, func() users.Manager {
		return users.NewManager(s.Store())
	})
}

func (s *BaseServer) SettingsManager() settings.Manager {
	return Create(s, func() settings.Manager {
		extraSettingsManager := integrations.NewManager(s.EventStore())

		idpConfig := settings.IdpConfig{}
		if s.Config.EmbeddedIdP != nil && s.Config.EmbeddedIdP.Enabled {
			idpConfig.EmbeddedIdpEnabled = true
			idpConfig.LocalAuthDisabled = s.Config.EmbeddedIdP.LocalAuthDisabled
		}

		return settings.NewManager(s.Store(), s.UsersManager(), extraSettingsManager, s.PermissionsManager(), idpConfig)
	})
}

func (s *BaseServer) PeersManager() peers.Manager {
	return Create(s, func() peers.Manager {
		manager := peers.NewManager(s.Store(), s.PermissionsManager())
		s.AfterInit(func(s *BaseServer) {
			manager.SetNetworkMapController(s.NetworkMapController())
			manager.SetIntegratedPeerValidator(s.IntegratedValidator())
			manager.SetAccountManager(s.AccountManager())
		})
		return manager
	})
}

func (s *BaseServer) AccountManager() account.Manager {
	return Create(s, func() account.Manager {
		accountManager, err := server.BuildManager(context.Background(), s.Config, s.Store(), s.NetworkMapController(), s.JobManager(), s.IdpManager(), s.mgmtSingleAccModeDomain, s.EventStore(), s.GeoLocationManager(), s.userDeleteFromIDPEnabled, s.IntegratedValidator(), s.Metrics(), s.ProxyController(), s.SettingsManager(), s.PermissionsManager(), s.Config.DisableDefaultPolicy)
		if err != nil {
			log.Fatalf("failed to create account manager: %v", err)
		}

		s.AfterInit(func(s *BaseServer) {
			accountManager.SetServiceManager(s.ReverseProxyManager())
		})

		return accountManager
	})
}

func (s *BaseServer) IdpManager() idp.Manager {
	return Create(s, func() idp.Manager {
		var idpManager idp.Manager
		var err error
		// Use embedded IdP manager if embedded Dex is configured and enabled.
		// Legacy IdpManager won't be used anymore even if configured.
		if s.Config.EmbeddedIdP != nil && s.Config.EmbeddedIdP.Enabled {
			idpManager, err = idp.NewEmbeddedIdPManager(context.Background(), s.Config.EmbeddedIdP, s.Metrics())
			if err != nil {
				log.Fatalf("failed to create embedded IDP manager: %v", err)
			}
			return idpManager
		}

		// Fall back to external IdP manager
		if s.Config.IdpManagerConfig != nil {
			idpManager, err = idp.NewManager(context.Background(), *s.Config.IdpManagerConfig, s.Metrics())
			if err != nil {
				log.Fatalf("failed to create IDP manager: %v", err)
			}
		}
		return idpManager
	})
}

// OAuthConfigProvider is only relevant when we have an embedded IdP manager. Otherwise must be nil
func (s *BaseServer) OAuthConfigProvider() idp.OAuthConfigProvider {
	if s.Config.EmbeddedIdP == nil || !s.Config.EmbeddedIdP.Enabled {
		return nil
	}

	idpManager := s.IdpManager()
	if idpManager == nil {
		return nil
	}

	// Reuse the EmbeddedIdPManager instance from IdpManager
	// EmbeddedIdPManager implements both idp.Manager and idp.OAuthConfigProvider
	if provider, ok := idpManager.(idp.OAuthConfigProvider); ok {
		return provider
	}
	return nil
}

func (s *BaseServer) GroupsManager() groups.Manager {
	return Create(s, func() groups.Manager {
		return groups.NewManager(s.Store(), s.PermissionsManager(), s.AccountManager())
	})
}

func (s *BaseServer) ResourcesManager() resources.Manager {
	return Create(s, func() resources.Manager {
		return resources.NewManager(s.Store(), s.PermissionsManager(), s.GroupsManager(), s.AccountManager(), s.ReverseProxyManager())
	})
}

func (s *BaseServer) RoutesManager() routers.Manager {
	return Create(s, func() routers.Manager {
		return routers.NewManager(s.Store(), s.PermissionsManager(), s.AccountManager())
	})
}

func (s *BaseServer) NetworksManager() networks.Manager {
	return Create(s, func() networks.Manager {
		return networks.NewManager(s.Store(), s.PermissionsManager(), s.ResourcesManager(), s.RoutesManager(), s.AccountManager())
	})
}

func (s *BaseServer) ZonesManager() zones.Manager {
	return Create(s, func() zones.Manager {
		return zonesManager.NewManager(s.Store(), s.AccountManager(), s.PermissionsManager(), s.DNSDomain())
	})
}

func (s *BaseServer) RecordsManager() records.Manager {
	return Create(s, func() records.Manager {
		return recordsManager.NewManager(s.Store(), s.AccountManager(), s.PermissionsManager())
	})
}

func (s *BaseServer) ReverseProxyManager() reverseproxy.Manager {
	return Create(s, func() reverseproxy.Manager {
		return nbreverseproxy.NewManager(s.Store(), s.AccountManager(), s.PermissionsManager(), s.ReverseProxyGRPCServer(), s.ReverseProxyDomainManager())
	})
}

func (s *BaseServer) ReverseProxyDomainManager() *manager.Manager {
	return Create(s, func() *manager.Manager {
		m := manager.NewManager(s.Store(), s.ReverseProxyGRPCServer(), s.PermissionsManager())
		return &m
	})
}
