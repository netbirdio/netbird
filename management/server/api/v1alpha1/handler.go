package v1alpha1

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/shared/management/http/apiv1alpha1"

	"github.com/netbirdio/netbird/management/server/permissions"

	peersmodule "github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/server/api/v1alpha1/peers"
	"github.com/netbirdio/netbird/management/server/api/v1alpha1/users"
)

func NewAPIV1Handler(
	ctx context.Context,
	router *mux.Router,
	accountManager account.Manager,
	peerManager peersmodule.Manager,
	networkMapController network_map.Controller,
	permissionsManager permissions.Manager) (http.Handler, error) {

	v1validatorMiddleware, err := apiv1alpha1.CreateV1ApiValidatingMiddleware()
	if err != nil {
		return nil, err
	}

	router.Use(v1validatorMiddleware.Handler)

	peersHandler := peers.NewHandler(accountManager, peerManager, networkMapController, permissionsManager)
	_ = peersHandler.WithEndpointsForRouter(router)

	usersHandler := users.NewHandler(accountManager)
	return usersHandler.WithEndpointsForRouter(router), nil
}
