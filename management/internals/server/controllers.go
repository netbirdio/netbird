package server

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/management-integrations/integrations"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	nmapcontroller "github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral"
	"github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral/manager"
	"github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/auth"
	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
)

func (s *BaseServer) PeersUpdateManager() network_map.PeersUpdateManager {
	return Create(s, func() network_map.PeersUpdateManager {
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

func (s *BaseServer) SecretsManager() grpc.SecretsManager {
	return Create(s, func() grpc.SecretsManager {
		secretsManager, err := grpc.NewTimeBasedAuthSecretsManager(s.PeersUpdateManager(), s.Config.TURNConfig, s.Config.Relay, s.SettingsManager(), s.GroupsManager())
		if err != nil {
			log.Fatalf("failed to create secrets manager: %v", err)
		}
		return secretsManager
	})
}

func (s *BaseServer) AuthManager() auth.Manager {
	audiences := s.Config.GetAuthAudiences()
	audience := s.Config.HttpConfig.AuthAudience
	keysLocation := s.Config.HttpConfig.AuthKeysLocation
	signingKeyRefreshEnabled := s.Config.HttpConfig.IdpSignKeyRefreshEnabled
	issuer := s.Config.HttpConfig.AuthIssuer
	userIDClaim := s.Config.HttpConfig.AuthUserIDClaim

	// Use embedded IdP configuration if available
	if oauthProvider := s.OAuthConfigProvider(); oauthProvider != nil {
		audiences = oauthProvider.GetClientIDs()
		if len(audiences) > 0 {
			audience = audiences[0] // Use the first client ID as the primary audience
		}
		// Use localhost keys location for internal validation (management has embedded Dex)
		keysLocation = oauthProvider.GetLocalKeysLocation()
		signingKeyRefreshEnabled = true
		issuer = oauthProvider.GetIssuer()
		userIDClaim = oauthProvider.GetUserIDClaim()
	}

	return Create(s, func() auth.Manager {
		return auth.NewManager(s.Store(),
			issuer,
			audience,
			keysLocation,
			userIDClaim,
			audiences,
			signingKeyRefreshEnabled)
	})
}

func (s *BaseServer) EphemeralManager() ephemeral.Manager {
	return Create(s, func() ephemeral.Manager {
		return manager.NewEphemeralManager(s.Store(), s.PeersManager())
	})
}

func (s *BaseServer) NetworkMapController() network_map.Controller {
	return Create(s, func() network_map.Controller {
		return nmapcontroller.NewController(context.Background(), s.Store(), s.Metrics(), s.PeersUpdateManager(), s.AccountRequestBuffer(), s.IntegratedValidator(), s.SettingsManager(), s.DNSDomain(), s.ProxyController(), s.EphemeralManager(), s.Config)
	})
}

func (s *BaseServer) AccountRequestBuffer() *server.AccountRequestBuffer {
	return Create(s, func() *server.AccountRequestBuffer {
		return server.NewAccountRequestBuffer(context.Background(), s.Store())
	})
}

func (s *BaseServer) DNSDomain() string {
	return s.dnsDomain
}
