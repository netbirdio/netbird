package apiv1alpha1

import (
	_ "embed"
	"log/slog"
	"os"

	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"
	"github.com/pb33f/libopenapi-validator/config"
	"github.com/pb33f/libopenapi/datamodel"
)

// TODO (dmitri) this needs to be extracted, as it will grow to 500Kb
//
//go:embed bundle.yaml
var bundle []byte

func CreateV1ApiValidator() (validator.Validator, error) {
	doc, err := libopenapi.NewDocumentWithConfiguration(bundle, &datamodel.DocumentConfiguration{
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
	})

	model, err := doc.BuildV3Model()
	if err != nil {
		return nil, err
	}

	// TODO figure out document validation: rn it's possible to have a spec
	// that's not entirely correct -- parts of it fail to parse, but silently
	return validator.NewValidatorFromV3Model(&model.Model,
		config.WithoutSecurityValidation(),
		config.WithStandardBodyDecoders(),
		config.WithRejectUnsupportedBodyContent(),
		config.WithRequestDefaults()), nil
	// v.SetDocument(doc)
	// v.ValidatePathParams()
	// if valid, errs := v.ValidateDocument(); !valid {
	// 	return nil, fmt.Errorf("error validating OpenAPI doc, %s", errs)
	// }
}
