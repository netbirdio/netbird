package mcpapi

import (
	"maps"
	"os"
	"slices"
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

// notExposed lists by area the operations of the public API spec that have no tool on purpose.
// An operation the spec gains needs a tool in catalog.go or an entry here with the reason it is
// left out. Giving a listed operation a tool means removing its entry.
var notExposed = []struct {
	reason     string
	operations []string
}{
	{
		reason: "A deployment may guard account deletion with middleware on the root router, as NetBird Cloud does for MSP tenants, and in-process dispatch does not pass through that router.",
		operations: []string{
			"DELETE /api/accounts/{accountId}",
		},
	},
	{
		reason: "Agent Network is not exposed yet.",
		operations: []string{
			"GET /api/agent-network/access-log-sessions",
			"GET /api/agent-network/access-logs",
			"GET /api/agent-network/agent-config",
			"GET /api/agent-network/budget-rules",
			"POST /api/agent-network/budget-rules",
			"GET /api/agent-network/budget-rules/{ruleId}",
			"PUT /api/agent-network/budget-rules/{ruleId}",
			"DELETE /api/agent-network/budget-rules/{ruleId}",
			"GET /api/agent-network/catalog/providers",
			"POST /api/agent-network/catalog/providers/models",
			"GET /api/agent-network/consumption",
			"GET /api/agent-network/guardrails",
			"POST /api/agent-network/guardrails",
			"GET /api/agent-network/guardrails/{guardrailId}",
			"PUT /api/agent-network/guardrails/{guardrailId}",
			"DELETE /api/agent-network/guardrails/{guardrailId}",
			"GET /api/agent-network/policies",
			"POST /api/agent-network/policies",
			"GET /api/agent-network/policies/{policyId}",
			"PUT /api/agent-network/policies/{policyId}",
			"DELETE /api/agent-network/policies/{policyId}",
			"GET /api/agent-network/providers",
			"POST /api/agent-network/providers",
			"GET /api/agent-network/providers/{providerId}",
			"PUT /api/agent-network/providers/{providerId}",
			"DELETE /api/agent-network/providers/{providerId}",
			"GET /api/agent-network/settings",
			"POST /api/agent-network/settings",
			"PUT /api/agent-network/settings",
			"DELETE /api/agent-network/settings",
			"GET /api/agent-network/usage/overview",
			"GET /api/integrations/agent-network/managed-proxy",
			"POST /api/integrations/agent-network/managed-proxy",
		},
	},
	{
		reason: "Reverse proxy services, domains and clusters are not exposed yet, and self-hosted proxy tokens are credentials.",
		operations: []string{
			"GET /api/reverse-proxies/clusters",
			"DELETE /api/reverse-proxies/clusters/{clusterAddress}",
			"GET /api/reverse-proxies/domains",
			"POST /api/reverse-proxies/domains",
			"DELETE /api/reverse-proxies/domains/{domainId}",
			"GET /api/reverse-proxies/domains/{domainId}/validate",
			"GET /api/reverse-proxies/proxy-tokens",
			"POST /api/reverse-proxies/proxy-tokens",
			"DELETE /api/reverse-proxies/proxy-tokens/{tokenId}",
			"GET /api/reverse-proxies/services",
			"POST /api/reverse-proxies/services",
			"GET /api/reverse-proxies/services/{serviceId}",
			"PUT /api/reverse-proxies/services/{serviceId}",
			"DELETE /api/reverse-proxies/services/{serviceId}",
		},
	},
	{
		reason: "Personal access tokens are credentials, and these operations mint and list them.",
		operations: []string{
			"GET /api/users/{userId}/tokens",
			"POST /api/users/{userId}/tokens",
			"GET /api/users/{userId}/tokens/{tokenId}",
			"DELETE /api/users/{userId}/tokens/{tokenId}",
		},
	},
	{
		reason: "Invite links and passwords are secrets, and resending an invitation emails the user.",
		operations: []string{
			"GET /api/users/invites",
			"POST /api/users/invites",
			"DELETE /api/users/invites/{inviteId}",
			"POST /api/users/invites/{inviteId}/regenerate",
			"GET /api/users/invites/{token}",
			"POST /api/users/invites/{token}/accept",
			"POST /api/users/{userId}/invite",
			"PUT /api/users/{userId}/password",
		},
	},
	{
		reason: "Creating or updating an identity provider takes its client secret, and identity provider setup is not exposed yet.",
		operations: []string{
			"GET /api/identity-providers",
			"POST /api/identity-providers",
			"GET /api/identity-providers/{idpId}",
			"PUT /api/identity-providers/{idpId}",
			"DELETE /api/identity-providers/{idpId}",
		},
	},
	{
		reason: "Instance status and bootstrap are not account management.",
		operations: []string{
			"GET /api/instance",
			"GET /api/instance/version",
			"POST /api/setup",
		},
	},
	{
		reason: "Peer jobs and temporary peer access are not exposed yet.",
		operations: []string{
			"GET /api/peers/{peerId}/jobs",
			"POST /api/peers/{peerId}/jobs",
			"GET /api/peers/{peerId}/jobs/{jobId}",
			"POST /api/peers/{peerId}/temporary-access",
		},
	},
	{
		reason: "Reverse proxy access logs are not exposed yet.",
		operations: []string{
			"GET /api/events/proxy",
		},
	},
}

// httpMethods are the keys of an OpenAPI path item that hold an operation.
var httpMethods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"patch": true, "head": true, "options": true, "trace": true,
}

func operationKey(method, path string) string {
	return strings.ToUpper(method) + " " + pathVariable.ReplaceAllString(path, "{}")
}

func (o specOperation) cloudOnly(cloudTags map[string]bool) bool {
	return o.CloudOnly || slices.ContainsFunc(o.Tags, func(tag string) bool { return cloudTags[tag] })
}

// TestPublicAPISpecIsCoveredByTheCatalog requires every operation of the public API spec that
// is not cloud only to have a tool or an entry in notExposed, so a new endpoint is a decision
// rather than a silent gap. It also refuses entries the spec or the catalog has overtaken.
func TestPublicAPISpecIsCoveredByTheCatalog(t *testing.T) {
	raw, err := os.ReadFile(specPath)
	require.NoError(t, err)
	var api spec
	require.NoError(t, yaml.Unmarshal(raw, &api))

	cloudTags := map[string]bool{}
	for _, tag := range api.Tags {
		cloudTags[tag.Name] = tag.CloudOnly
	}

	tools := map[string]string{}
	for _, op := range catalog {
		key := operationKey(op.method, op.path)
		if other, ok := tools[key]; ok {
			assert.Fail(t, "operation has two tools",
				"%s is served by both %s and %s. Keep one tool per operation in catalog.go.", key, other, op.name)
		}
		tools[key] = op.name
	}
	excluded := map[string]bool{}
	for _, area := range notExposed {
		assert.NotEmpty(t, area.reason, "every notExposed area needs a reason: %v", area.operations)
		for _, entry := range area.operations {
			method, path, ok := strings.Cut(entry, " ")
			require.True(t, ok, "notExposed entry %q must read \"METHOD /path\"", entry)
			key := operationKey(method, path)
			assert.False(t, excluded[key], "notExposed lists %s twice", entry)
			excluded[key] = true
			if tool, ok := tools[key]; ok {
				assert.Fail(t, "operation has a tool and a notExposed entry",
					"%s is served by the tool %s. Remove it from notExposed in openapi_test.go.", entry, tool)
			}
		}
	}

	public := map[string]bool{}
	for _, path := range slices.Sorted(maps.Keys(api.Paths)) {
		item := api.Paths[path]
		for _, method := range slices.Sorted(maps.Keys(item)) {
			if !httpMethods[method] {
				continue
			}
			var documented specOperation
			node := item[method]
			require.NoError(t, node.Decode(&documented), "%s %s", method, path)
			if documented.cloudOnly(cloudTags) {
				continue
			}
			key := operationKey(method, path)
			public[key] = true
			_, hasTool := tools[key]
			assert.True(t, hasTool || excluded[key],
				"%s %s is in the public API spec but has no MCP tool. Add a tool for it to catalog.go, "+
					"or add it to notExposed in openapi_test.go with the reason it is left out.",
				strings.ToUpper(method), path)
		}
	}

	for _, area := range notExposed {
		for _, entry := range area.operations {
			method, path, _ := strings.Cut(entry, " ")
			assert.True(t, public[operationKey(method, path)],
				"notExposed lists %s, which the public API spec no longer documents or marks cloud only. "+
					"Remove it from notExposed in openapi_test.go.", entry)
		}
	}
}
