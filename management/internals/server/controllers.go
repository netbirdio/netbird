package server

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/management-integrations/integrations"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/auth"
	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
)

func (s *BaseServer) PeersUpdateManager() *server.PeersUpdateManager {
	return Create(s, func() *server.PeersUpdateManager {
		return server.NewPeersUpdateManager(s.Metrics())
	})
}

func (s *BaseServer) JobManager() *server.JobManager {
	return Create(s, func() *server.JobManager {
		return server.NewJobManager(s.Metrics(), s.Store())
	})
}

func (s *BaseServer) IntegratedValidator() integrated_validator.IntegratedValidator {
	return Create(s, func() integrated_validator.IntegratedValidator {
		integratedPeerValidator, err := integrations.NewIntegratedValidator(context.Background(), s.EventStore())
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

func (s *BaseServer) SecretsManager() *server.TimeBasedAuthSecretsManager {
	return Create(s, func() *server.TimeBasedAuthSecretsManager {
		return server.NewTimeBasedAuthSecretsManager(s.PeersUpdateManager(), s.config.TURNConfig, s.config.Relay, s.SettingsManager(), s.GroupsManager())
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

func (s *BaseServer) EphemeralManager() *server.EphemeralManager {
	return Create(s, func() *server.EphemeralManager {
		return server.NewEphemeralManager(s.Store(), s.AccountManager())
	})
}
