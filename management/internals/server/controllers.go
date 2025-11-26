package server

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/management-integrations/integrations"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	nmapcontroller "github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/auth"
	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	"github.com/netbirdio/netbird/management/server/peers/ephemeral"
	"github.com/netbirdio/netbird/management/server/peers/ephemeral/manager"
)

func (s *BaseServer) PeersUpdateManager() network_map.PeersUpdateManager {
	return Create(s, func() *update_channel.PeersUpdateManager {
		return update_channel.NewPeersUpdateManager(s.Metrics())
	})
}

func (s *BaseServer) IntegratedValidator() integrated_validator.IntegratedValidator {
	return Create(s, func() integrated_validator.IntegratedValidator {
		integratedPeerValidator, err := integrations.NewIntegratedValidator(
			context.Background(),
			s.PeersManager(),
			s.SettingsManager(),
			s.EventStore())
		if err != nil {
			log.Errorf("failed to create integrated peer validator: %v", err)
		}
		return integratedPeerValidator
	})
}

func (s *BaseServer) ProxyController() port_forwarding.Controller {
	return Create(s, func() port_forwarding.Controller {
		return integrations.NewController(s.Store())
	})
}

func (s *BaseServer) SecretsManager() *grpc.TimeBasedAuthSecretsManager {
	return Create(s, func() *grpc.TimeBasedAuthSecretsManager {
		return grpc.NewTimeBasedAuthSecretsManager(s.PeersUpdateManager(), s.config.TURNConfig, s.config.Relay, s.SettingsManager(), s.GroupsManager())
	})
}

func (s *BaseServer) AuthManager() auth.Manager {
	return Create(s, func() auth.Manager {
		return auth.NewManager(s.Store(),
			s.config.HttpConfig.AuthIssuer,
			s.config.HttpConfig.AuthAudience,
			s.config.HttpConfig.AuthKeysLocation,
			s.config.HttpConfig.AuthUserIDClaim,
			s.config.GetAuthAudiences(),
			s.config.HttpConfig.IdpSignKeyRefreshEnabled)
	})
}

func (s *BaseServer) EphemeralManager() ephemeral.Manager {
	return Create(s, func() ephemeral.Manager {
		return manager.NewEphemeralManager(s.Store(), s.AccountManager())
	})
}

func (s *BaseServer) NetworkMapController() network_map.Controller {
	return Create(s, func() *nmapcontroller.Controller {
		return nmapcontroller.NewController(context.Background(), s.Store(), s.Metrics(), s.PeersUpdateManager(), s.AccountRequestBuffer(), s.IntegratedValidator(), s.SettingsManager(), s.dnsDomain, s.ProxyController(), s.config)
	})
}

func (s *BaseServer) AccountRequestBuffer() *server.AccountRequestBuffer {
	return Create(s, func() *server.AccountRequestBuffer {
		return server.NewAccountRequestBuffer(context.Background(), s.Store())
	})
}
