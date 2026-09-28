package v1alpha1

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofiber/fiber/v2/log"
	"github.com/gorilla/mux"
	"github.com/pb33f/libopenapi"
	"github.com/pb33f/libopenapi-validator/config"
	"github.com/pb33f/libopenapi/bundler"
	"github.com/pb33f/libopenapi/datamodel"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"

	"github.com/netbirdio/netbird/management/server/permissions"

	"github.com/netbirdio/netbird/management/server/api/v1alpha1/peers"

	validator "github.com/pb33f/libopenapi-validator"
)

func NewAPIV1Handler(
	ctx context.Context,
	router *mux.Router,
	accountManager account.Manager,
	networkMapController network_map.Controller,
	permissionsManager permissions.Manager) (http.Handler, error) {

	model, err := generateV1Bindings()
	if err != nil {
		return nil, err
	}

	v := validator.NewValidatorFromV3Model(model,
		config.WithStandardBodyDecoders(),
		config.WithRejectUnsupportedBodyContent(),
		config.WithRequestDefaults())

	// v.ValidatePathParams()

	router.Use((&V1ValidatorMiddleware{v: v}).Handler)

	peers.AddEndpoints(accountManager, router, networkMapController, permissionsManager)
	return router, nil
}

var apiPath = filepath.Join("shared", "management", "http", "apiv1alpha1")

func generateV1Bindings() (*v3.Document, error) {
	specFile, err := os.ReadFile(filepath.Join(apiPath, "openapi.yaml"))
	if err != nil {
		return nil, err
	}

	multiFileDoc, err := libopenapi.NewDocumentWithConfiguration(specFile, &datamodel.DocumentConfiguration{
		AllowFileReferences:     true,
		BasePath:                apiPath,
		SpecFilePath:            filepath.Join(apiPath, "openapi.yaml"),
		ExtractRefsSequentially: true,
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelError,
		})),
		TransformSiblingRefs:      true,                    // enable openapi 3.1 compliance by default
		MergeReferencedProperties: true,                    // enable enhanced resolution by default
		PropertyMergeStrategy:     datamodel.PreserveLocal, // local properties take precedence
	})
	if err != nil {
		return nil, err
	}
	multiFileModel, err := multiFileDoc.BuildV3Model()
	if err != nil {
		return nil, err
	}

	bundle, err := bundler.BundleDocumentComposed(&multiFileModel.Model, &bundler.BundleCompositionConfig{
		StrictValidation: true,
	})
	if err != nil {
		return nil, err
	}

	doc, err := libopenapi.NewDocumentWithConfiguration(bundle, &datamodel.DocumentConfiguration{
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelError,
		})),
	})
	if err != nil {
		return nil, err
	}

	model, err := doc.BuildV3Model()
	if err != nil {
		return nil, err
	}

	return &model.Model, nil
}

type V1ValidatorMiddleware struct {
	v validator.Validator
}

func (v *V1ValidatorMiddleware) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		valid, errs := v.v.ValidateHttpRequest(r)
		if !valid {
			validationErrs := make([]string, len(errs))
			for _, err := range errs {
				validationErrs = append(validationErrs, err.Message)
			}
			log.WithContext(r.Context()).Errorf("Error validating request: %s", strings.Join(validationErrs, ", "))
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid request: %s", strings.Join(validationErrs, ", ")), w)

			return
		}
		h.ServeHTTP(w, r)
	})
}
