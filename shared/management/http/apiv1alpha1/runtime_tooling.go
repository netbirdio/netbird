package apiv1alpha1

import (
	_ "embed"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"
	"github.com/pb33f/libopenapi-validator/config"
	"github.com/pb33f/libopenapi-validator/errors"
	"github.com/pb33f/libopenapi/datamodel"
	log "github.com/sirupsen/logrus"
)

// TODO (dmitri) this needs to be extracted, as it will grow to 500Kb
//
//go:embed bundle.yaml
var bundle []byte

func CreateV1ApiValidatingMiddleware() (*V1ValidatorMiddleware, error) {
	doc, err := libopenapi.NewDocumentWithConfiguration(bundle, &datamodel.DocumentConfiguration{
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
	})
	if err != nil {
		return nil, err
	}

	model, err := doc.BuildV3Model()
	if err != nil {
		return nil, err
	}

	// TODO figure out document validation: rn it's possible to have a spec
	// that's not entirely correct -- parts of it fail to parse, but silently
	v := validator.NewValidatorFromV3Model(&model.Model,
		config.WithoutSecurityValidation(),
		config.WithStandardBodyDecoders(),
		config.WithRejectUnsupportedBodyContent(),
		config.WithRequestDefaults())
	// v.SetDocument(doc)
	// v.ValidatePathParams()
	// if valid, errs := v.ValidateDocument(); !valid {
	// 	return nil, fmt.Errorf("error validating OpenAPI doc, %s", errs)
	// }

	return &V1ValidatorMiddleware{Validator: v}, nil
}

type V1ValidatorMiddleware struct {
	Validator validator.Validator
}

func (v *V1ValidatorMiddleware) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		valid, errs := v.Validator.ValidateHttpRequestSync(r)
		if !valid {
			validationErrs := make([]string, 0, len(errs))
			for _, err := range errs {
				validationErrs = append(validationErrs, validationError(err))
			}

			log.WithContext(r.Context()).Debugf("error validating request: %s", strings.Join(validationErrs, ", "))
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
