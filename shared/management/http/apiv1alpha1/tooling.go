package apiv1alpha1

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/pb33f/libopenapi"
	"github.com/pb33f/libopenapi/bundler"
	"github.com/pb33f/libopenapi/datamodel"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
	"github.com/pb33f/libopenapi/generator/golang"
)

var ApiPath = filepath.Join("shared", "management", "http", "apiv1alpha1", "openapi.yaml")

func GenerateV1ApiBindings(openapipath string) ([]byte, *v3.Document, error) {
	specFile, err := os.ReadFile(openapipath)
	if err != nil {
		return nil, nil, err
	}

	multiFileDoc, err := libopenapi.NewDocumentWithConfiguration(specFile, &datamodel.DocumentConfiguration{
		AllowFileReferences:     true,
		BasePath:                filepath.Dir(openapipath),
		SpecFilePath:            filepath.Join(openapipath),
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

	return bundle, &model.Model, nil
}

func GenerateV1Schema(model *v3.Document) (*golang.GeneratedFile, error) {
	// render every schema in components.schemas into one file
	gen := golang.NewGenerator(
		golang.WithGeneratedComment(true),
		golang.WithFormatMapping("date-time", "time.Time", "time"),
		golang.WithOptionalFieldsAsPointers(true),
		golang.WithEnumConstants(true),
		golang.WithNestedTypeNameDelimiter(""),
		golang.WithPackageName("apiv1alpha1"),
		golang.WithFieldNameResolver(toPublicName))

	return gen.RenderSchemas(model.Components.Schemas)
}

// this is to keep existing naming of fields like "id", "url", etc
// libopenapi by default converts them to all-uppercase, like "ID", "URL", etc
func toPublicName(name string) string {
	parts := splitIdentifier(name)
	if len(parts) == 0 {
		return "Value"
	}
	var b strings.Builder
	for _, p := range parts {
		rs := []rune(strings.ToLower(p))
		rs[0] = unicode.ToUpper(rs[0])
		b.WriteString(string(rs))
	}
	out := b.String()
	first := []rune(out)[0]
	if unicode.IsDigit(first) {
		return "Value" + out
	}
	return out
}

func splitIdentifier(name string) []string {
	var raw []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			raw = append(raw, b.String())
			b.Reset()
		}
	}
	for _, r := range name {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		default:
			flush()
		}
	}
	flush()
	var parts []string
	for _, part := range raw {
		parts = append(parts, splitCamel(part)...)
	}
	return parts
}

func splitCamel(value string) []string {
	rs := []rune(value)
	if len(rs) == 0 {
		return nil
	}
	var parts []string
	start := 0
	for i := 1; i < len(rs); i++ {
		prev := rs[i-1]
		cur := rs[i]
		var next rune
		if i+1 < len(rs) {
			next = rs[i+1]
		}
		lowerToUpper := unicode.IsLower(prev) && unicode.IsUpper(cur)
		acronymToWord := unicode.IsUpper(prev) && unicode.IsUpper(cur) && next != 0 && unicode.IsLower(next)
		if lowerToUpper || acronymToWord {
			parts = append(parts, string(rs[start:i]))
			start = i
		}
	}
	parts = append(parts, string(rs[start:]))
	return parts
}
