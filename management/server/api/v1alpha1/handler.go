package v1alpha1

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
	"github.com/pb33f/libopenapi"
	"github.com/pb33f/libopenapi-validator/config"
	"github.com/pb33f/libopenapi-validator/errors"
	"github.com/pb33f/libopenapi/bundler"
	"github.com/pb33f/libopenapi/datamodel"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
	log "github.com/sirupsen/logrus"

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

	_, model, err := generateV1Bindings()
	if err != nil {
		return nil, err
	}

	// TODO figureout document validation: rn it's possible to have a spec
	// that's not entirely correct -- parts of it fail to parse, but silently
	v := validator.NewValidatorFromV3Model(model,
		config.WithoutSecurityValidation(),
		config.WithStandardBodyDecoders(),
		config.WithRejectUnsupportedBodyContent(),
		config.WithRequestDefaults())
	// v.SetDocument(doc)
	// v.ValidatePathParams()
	// if valid, errs := v.ValidateDocument(); !valid {
	// 	return nil, fmt.Errorf("error validating OpenAPI doc, %s", errs)
	// }

	router.Use((&V1ValidatorMiddleware{v: v}).Handler)

	peers.AddEndpoints(accountManager, router, networkMapController, permissionsManager)
	return router, nil
}

var apiPath = filepath.Join("shared", "management", "http", "apiv1alpha1")

func generateV1Bindings() (libopenapi.Document, *v3.Document, error) {
	specFile, err := os.ReadFile(filepath.Join(apiPath, "openapi.yaml"))
	if err != nil {
		return nil, nil, err
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
		return nil, nil, err
	}
	multiFileModel, err := multiFileDoc.BuildV3Model()
	if err != nil {
		return nil, nil, err
	}

	bundle, err := bundler.BundleDocumentComposed(&multiFileModel.Model, &bundler.BundleCompositionConfig{
		StrictValidation: true,
	})
	if err != nil {
		return nil, nil, err
	}

	slog.Info(string(bundle))

	doc, err := libopenapi.NewDocumentWithConfiguration(bundle, &datamodel.DocumentConfiguration{
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
	})
	if err != nil {
		return nil, nil, err
	}

	model, err := doc.BuildV3Model()
	if err != nil {
		return nil, nil, err
	}

	return doc, &model.Model, nil
}

type V1ValidatorMiddleware struct {
	v validator.Validator
}

func (v *V1ValidatorMiddleware) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		valid, errs := v.v.ValidateHttpRequest(r)
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
