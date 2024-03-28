package integrations

import (
	"context"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/activity/sqlite"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
)

func RegisterHandlers(
	ctx context.Context,
	prefix string,
	router *mux.Router,
	accountManager server.AccountManager,
	extractor *jwtclaims.ClaimsExtractor,
) (*mux.Router, error) {
	return router, nil
}

func InitEventStore(dataDir string, key string) (activity.Store, string, error) {
	var err error
	if key == "" {
		log.Debugf("generate new activity store encryption key")
		key, err = sqlite.GenerateKey()
		if err != nil {
			return nil, "", err
		}
	}
	store, err := sqlite.NewSQLiteStore(dataDir, key)
	return store, key, err
}
