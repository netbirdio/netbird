package v1alpha1

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/pb33f/libopenapi-validator/errors"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/shared/management/http/apiv1alpha1"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"

	"github.com/netbirdio/netbird/management/server/permissions"

	"github.com/netbirdio/netbird/management/server/api/v1alpha1/peers"
	"github.com/netbirdio/netbird/management/server/api/v1alpha1/users"

	validator "github.com/pb33f/libopenapi-validator"
)

func NewAPIV1Handler(
	ctx context.Context,
	router *mux.Router,
	accountManager account.Manager,
	networkMapController network_map.Controller,
	permissionsManager permissions.Manager) (http.Handler, error) {

	v1validator, err := apiv1alpha1.CreateV1ApiValidator()
	if err != nil {
		return nil, err
	}

	router.Use((&V1ValidatorMiddleware{v: v1validator}).Handler)

	peersHandler := peers.NewHandler(accountManager, networkMapController, permissionsManager)
	_ = peersHandler.WithEndpointsForRouter(router)

	usersHandler := users.NewHandler(accountManager)
	return usersHandler.WithEndpointsForRouter(router), nil
}

type V1ValidatorMiddleware struct {
	v validator.Validator
}

func (v *V1ValidatorMiddleware) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		valid, errs := v.v.ValidateHttpRequestSync(r)
		if !valid {
			validationErrs := make([]string, 0, len(errs))
			for _, err := range errs {
				validationErrs = append(validationErrs, validationError(err))
			}

			log.WithContext(r.Context()).Errorf("error validating request: %s", strings.Join(validationErrs, ", "))
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid request: %s", strings.Join(validationErrs, ", ")), w)

			return
		}
		h.ServeHTTP(w, r)
	})
}

func validationError(err *errors.ValidationError) string {
	if err.SchemaValidationErrors != nil {
		errs := make([]string, 0, len(err.SchemaValidationErrors))
		for _, e := range err.SchemaValidationErrors {
			errs = append(errs, fmt.Sprintf("field %s: %s", e.FieldPath, e.Reason))
		}
		return fmt.Sprintf("%s: %s", err.Message, strings.Join(errs, ", "))
	} else {
		if err.SpecLine > 0 && err.SpecCol > 0 {
			return fmt.Sprintf("%s, Line: %d, Column: %d", err.Message, err.SpecLine, err.SpecCol)
		} else {
			return fmt.Sprint(err.Message)
		}
	}
}
