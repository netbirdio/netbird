package mcpapi

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// specPath is the public REST API specification the catalog is held to.
const specPath = "../../../../shared/management/http/api/openapi.yml"

type specParameter struct {
	Name string `yaml:"name"`
	In   string `yaml:"in"`
}

type specOperation struct {
	Tags        []string        `yaml:"tags"`
	CloudOnly   bool            `yaml:"x-cloud-only"`
	Parameters  []specParameter `yaml:"parameters"`
	RequestBody *struct {
		Content map[string]struct {
			Schema struct {
				Ref string `yaml:"$ref"`
			} `yaml:"schema"`
		} `yaml:"content"`
	} `yaml:"requestBody"`
}

type spec struct {
	Tags []struct {
		Name      string `yaml:"name"`
		CloudOnly bool   `yaml:"x-cloud-only"`
	} `yaml:"tags"`
	Paths map[string]map[string]yaml.Node `yaml:"paths"`
}

// TestCatalogIsInThePublicAPISpec holds every tool to an operation the public OpenAPI spec
// documents and every NetBird server serves: the same method and path, only documented query
// parameters, and the request body the spec names.
func TestCatalogIsInThePublicAPISpec(t *testing.T) {
	raw, err := os.ReadFile(specPath)
	require.NoError(t, err)
	var api spec
	require.NoError(t, yaml.Unmarshal(raw, &api))

	cloudTags := map[string]bool{}
	for _, tag := range api.Tags {
		cloudTags[tag.Name] = tag.CloudOnly
	}
	paths := map[string]map[string]yaml.Node{}
	for path, item := range api.Paths {
		paths[pathVariable.ReplaceAllString(path, "{}")] = item
	}

	for _, op := range catalog {
		t.Run(op.name, func(t *testing.T) {
			item, ok := paths[pathVariable.ReplaceAllString(op.path, "{}")]
			require.True(t, ok, "%s is not in the public API spec", op.path)
			node, ok := item[strings.ToLower(op.method)]
			require.True(t, ok, "%s %s is not in the public API spec", op.method, op.path)
			var documented specOperation
			require.NoError(t, node.Decode(&documented))

			assert.False(t, documented.CloudOnly, "%s %s is cloud only", op.method, op.path)
			for _, tag := range documented.Tags {
				assert.False(t, cloudTags[tag], "%s %s is tagged %s, which is cloud only", op.method, op.path, tag)
			}

			query := map[string]bool{}
			for _, p := range documented.Parameters {
				if p.In == "query" {
					query[p.Name] = true
				}
			}
			for _, q := range op.query {
				assert.True(t, query[q.name], "query parameter %q of %s %s is not documented", q.name, op.method, op.path)
			}

			if op.body == nil {
				assert.Nil(t, documented.RequestBody, "%s %s documents a request body the tool does not send", op.method, op.path)
				return
			}
			require.NotNil(t, documented.RequestBody, "%s %s documents no request body", op.method, op.path)
			ref := documented.RequestBody.Content["application/json"].Schema.Ref
			assert.Equal(t, "#/components/schemas/"+op.body.Name(), ref, "request body of %s %s", op.method, op.path)
		})
	}
}
