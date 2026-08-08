package proxy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// The proxy is the last line of defence for domain ownership: a mapping that
// management has not marked validated is refused before any route, relay or
// certificate order is set up, whatever mode it claims.
func TestSetupMappingRoutes_RefusesUnvalidatedDomain(t *testing.T) {
	s := &Server{Logger: quietLogger()}

	for _, mode := range []string{"", "http", "tcp", "udp", "tls"} {
		name := mode
		if name == "" {
			name = "unset"
		}
		t.Run(name, func(t *testing.T) {
			mapping := &proto.ProxyMapping{
				Type:            proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
				Id:              "svc-1",
				AccountId:       "acc-1",
				Domain:          "unproven.example.com",
				Mode:            mode,
				DomainValidated: false,
				Path:            []*proto.PathMapping{{Path: "/", Target: "http://10.0.0.1:8080"}},
			}

			err := s.setupMappingRoutes(context.Background(), mapping)
			require.Error(t, err, "an unvalidated mapping must not be set up")
			assert.Contains(t, err.Error(), "not validated")
		})
	}
}
