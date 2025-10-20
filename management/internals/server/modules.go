package server

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/management-integrations/integrations"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/networks"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	"github.com/netbirdio/netbird/management/server/peers"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/users"
)

func (s *BaseServer) GeoLocationManager() geolocation.Geolocation {
	return Create(s, func() geolocation.Geolocation {
		geo, err := geolocation.NewGeolocation(context.Background(), s.config.Datadir, !s.disableGeoliteUpdate)
		if err != nil {
			log.Fatalf("could not initialize geolocation service: %v", err)
		}

		log.Infof("geolocation service has been initialized from %s", s.config.Datadir)

		return geo
	})
}

func (s *BaseServer) PermissionsManager() permissions.Manager {
	return Create(s, func() permissions.Manager {
		return permissions.NewManager(s.Store())
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
		return settings.NewManager(s.Store(), s.UsersManager(), extraSettingsManager, s.PermissionsManager())
	})
}

func (s *BaseServer) PeersManager() peers.Manager {
	return Create(s, func() peers.Manager {
		return peers.NewManager(s.Store(), s.PermissionsManager())
	})
}

func (s *BaseServer) AccountManager() account.Manager {
	return Create(s, func() account.Manager {
		accountManager, err := server.BuildManager(context.Background(), s.Store(), s.PeersUpdateManager(), s.IdpManager(), s.mgmtSingleAccModeDomain,
			s.dnsDomain, s.EventStore(), s.GeoLocationManager(), s.userDeleteFromIDPEnabled, s.IntegratedValidator(), s.Metrics(), s.ProxyController(), s.SettingsManager(), s.PermissionsManager(), s.config.DisableDefaultPolicy)
		if err != nil {
			log.Fatalf("failed to create account manager: %v", err)
		}

		s.AfterInit(func(s *BaseServer) {
			accountManager.SetEphemeralManager(s.EphemeralManager())
		})
		return accountManager
	})
}

func (s *BaseServer) IdpManager() idp.Manager {
	return Create(s, func() idp.Manager {
		var idpManager idp.Manager
		var err error
		if s.config.IdpManagerConfig != nil {
			idpManager, err = idp.NewManager(context.Background(), *s.config.IdpManagerConfig, s.Metrics())
			if err != nil {
				log.Fatalf("failed to create IDP manager: %v", err)
			}
		}
		return idpManager
	})
}

func (s *BaseServer) GroupsManager() groups.Manager {
	return Create(s, func() groups.Manager {
		return groups.NewManager(s.Store(), s.PermissionsManager(), s.AccountManager())
	})
}

func (s *BaseServer) ResourcesManager() resources.Manager {
	return Create(s, func() resources.Manager {
		return resources.NewManager(s.Store(), s.PermissionsManager(), s.GroupsManager(), s.AccountManager())
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
