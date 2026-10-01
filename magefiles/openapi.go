package main

import (
	"os"
	"path/filepath"

	"github.com/magefile/mage/mg"
	"github.com/netbirdio/netbird/shared/management/http/apiv1alpha1"
)

var apiPath = filepath.Join("shared", "management", "http", "apiv1alpha1")

type Openapi mg.Namespace

func (Openapi) GenerateV1Bindings(generateflags *string) error {
	bundle, model, err := apiv1alpha1.GenerateV1ApiBindings(apiv1alpha1.ApiPath)
	if err != nil {
		return err
	}
	err = os.WriteFile(filepath.Join(apiPath, "bundle.yaml"), bundle, 0644)
	if err != nil {
		return err
	}

	generated, err := apiv1alpha1.GenerateV1Schema(model)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(apiPath, "types.gen.go"), generated.Source, 0644)
}
