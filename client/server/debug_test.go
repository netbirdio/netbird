package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/anonymize"
)

func TestAnonymizeStateFile(t *testing.T) {
	testState := map[string]json.RawMessage{
		"null_state": json.RawMessage("null"),
		"test_state": mustMarshal(map[string]any{
			// Test simple fields
			"public_ip":      "203.0.113.1",
			"private_ip":     "192.168.1.1",
			"protected_ip":   "100.64.0.1",
			"well_known_ip":  "8.8.8.8",
			"ipv6_addr":      "2001:db8::1",
			"private_ipv6":   "fd00::1",
			"domain":         "test.example.com",
			"uri":            "stun:stun.example.com:3478",
			"uri_with_ip":    "turn:203.0.113.1:3478",
			"netbird_domain": "device.netbird.cloud",

			// Test CIDR ranges
			"public_cidr":       "203.0.113.0/24",
			"private_cidr":      "192.168.0.0/16",
			"protected_cidr":    "100.64.0.0/10",
			"ipv6_cidr":         "2001:db8::/32",
			"private_ipv6_cidr": "fd00::/8",

			// Test nested structures
			"nested": map[string]any{
				"ip":     "203.0.113.2",
				"domain": "nested.example.com",
				"more_nest": map[string]any{
					"ip":     "203.0.113.3",
					"domain": "deep.example.com",
				},
			},

			// Test arrays
			"string_array": []any{
				"203.0.113.4",
				"test1.example.com",
				"test2.example.com",
			},
			"object_array": []any{
				map[string]any{
					"ip":     "203.0.113.5",
					"domain": "array1.example.com",
				},
				map[string]any{
					"ip":     "203.0.113.6",
					"domain": "array2.example.com",
				},
			},

			// Test multiple occurrences of same value
			"duplicate_ip":     "203.0.113.1",      // Same as public_ip
			"duplicate_domain": "test.example.com", // Same as domain

			// Test URIs with various schemes
			"stun_uri":  "stun:stun.example.com:3478",
			"turns_uri": "turns:turns.example.com:5349",
			"http_uri":  "http://web.example.com:80",
			"https_uri": "https://secure.example.com:443",

			// Test strings that might look like IPs but aren't
			"not_ip":         "300.300.300.300",
			"partial_ip":     "192.168",
			"ip_like_string": "1234.5678",

			// Test mixed content strings
			"mixed_content": "Server at 203.0.113.1 (test.example.com) on port 80",

			// Test empty and special values
			"empty_string":  "",
			"null_value":    nil,
			"numeric_value": 42,
			"boolean_value": true,
		}),
		"route_state": mustMarshal(map[string]any{
			"routes": []any{
				map[string]any{
					"network": "203.0.113.0/24",
					"gateway": "203.0.113.1",
					"domains": []any{
						"route1.example.com",
						"route2.example.com",
					},
				},
				map[string]any{
					"network": "2001:db8::/32",
					"gateway": "2001:db8::1",
					"domains": []any{
						"route3.example.com",
						"route4.example.com",
					},
				},
			},
			// Test map with IP/CIDR keys
			"refCountMap": map[string]any{
				"203.0.113.1/32": map[string]any{
					"Count": 1,
					"Out": map[string]any{
						"IP": "192.168.0.1",
						"Intf": map[string]any{
							"Name":  "eth0",
							"Index": 1,
						},
					},
				},
				"2001:db8::1/128": map[string]any{
					"Count": 1,
					"Out": map[string]any{
						"IP": "fe80::1",
						"Intf": map[string]any{
							"Name":  "eth0",
							"Index": 1,
						},
					},
				},
				"10.0.0.1/32": map[string]any{ // private IP should remain unchanged
					"Count": 1,
					"Out": map[string]any{
						"IP": "192.168.0.1",
					},
				},
			},
		}),
	}

	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())

	// Pre-seed the domains we need to verify in the test assertions
	anonymizer.AnonymizeDomain("test.example.com")
	anonymizer.AnonymizeDomain("nested.example.com")
	anonymizer.AnonymizeDomain("deep.example.com")
	anonymizer.AnonymizeDomain("array1.example.com")

	err := anonymizeStateFile(&testState, anonymizer)
	require.NoError(t, err)

	// Helper function to unmarshal and get nested values
	var state map[string]any
	err = json.Unmarshal(testState["test_state"], &state)
	require.NoError(t, err)

	// Test null state remains unchanged
	require.Equal(t, "null", string(testState["null_state"]))

	// Basic assertions
	assert.NotEqual(t, "203.0.113.1", state["public_ip"])
	assert.Equal(t, "192.168.1.1", state["private_ip"])  // Private IP unchanged
	assert.Equal(t, "100.64.0.1", state["protected_ip"]) // Protected IP unchanged
	assert.Equal(t, "8.8.8.8", state["well_known_ip"])   // Well-known IP unchanged
	assert.NotEqual(t, "2001:db8::1", state["ipv6_addr"])
	assert.Equal(t, "fd00::1", state["private_ipv6"]) // Private IPv6 unchanged
	assert.NotEqual(t, "test.example.com", state["domain"])
	assert.True(t, strings.HasSuffix(state["domain"].(string), ".domain"))
	assert.Equal(t, "device.netbird.cloud", state["netbird_domain"]) // Netbird domain unchanged

	// CIDR ranges
	assert.NotEqual(t, "203.0.113.0/24", state["public_cidr"])
	assert.Contains(t, state["public_cidr"], "/24")           // Prefix preserved
	assert.Equal(t, "192.168.0.0/16", state["private_cidr"])  // Private CIDR unchanged
	assert.Equal(t, "100.64.0.0/10", state["protected_cidr"]) // Protected CIDR unchanged
	assert.NotEqual(t, "2001:db8::/32", state["ipv6_cidr"])
	assert.Contains(t, state["ipv6_cidr"], "/32") // IPv6 prefix preserved

	// Nested structures
	nested := state["nested"].(map[string]any)
	assert.NotEqual(t, "203.0.113.2", nested["ip"])
	assert.NotEqual(t, "nested.example.com", nested["domain"])
	moreNest := nested["more_nest"].(map[string]any)
	assert.NotEqual(t, "203.0.113.3", moreNest["ip"])
	assert.NotEqual(t, "deep.example.com", moreNest["domain"])

	// Arrays
	strArray := state["string_array"].([]any)
	assert.NotEqual(t, "203.0.113.4", strArray[0])
	assert.NotEqual(t, "test1.example.com", strArray[1])
	assert.True(t, strings.HasSuffix(strArray[1].(string), ".domain"))

	objArray := state["object_array"].([]any)
	firstObj := objArray[0].(map[string]any)
	assert.NotEqual(t, "203.0.113.5", firstObj["ip"])
	assert.NotEqual(t, "array1.example.com", firstObj["domain"])

	// Duplicate values should be anonymized consistently
	assert.Equal(t, state["public_ip"], state["duplicate_ip"])
	assert.Equal(t, state["domain"], state["duplicate_domain"])

	// URIs
	assert.NotContains(t, state["stun_uri"], "stun.example.com")
	assert.NotContains(t, state["turns_uri"], "turns.example.com")
	assert.NotContains(t, state["http_uri"], "web.example.com")
	assert.NotContains(t, state["https_uri"], "secure.example.com")

	// Non-IP strings should remain unchanged
	assert.Equal(t, "300.300.300.300", state["not_ip"])
	assert.Equal(t, "192.168", state["partial_ip"])
	assert.Equal(t, "1234.5678", state["ip_like_string"])

	// Mixed content should have IPs and domains replaced
	mixedContent := state["mixed_content"].(string)
	assert.NotContains(t, mixedContent, "203.0.113.1")
	assert.NotContains(t, mixedContent, "test.example.com")
	assert.Contains(t, mixedContent, "Server at ")
	assert.Contains(t, mixedContent, " on port 80")

	// Special values should remain unchanged
	assert.Equal(t, "", state["empty_string"])
	assert.Nil(t, state["null_value"])
	assert.Equal(t, float64(42), state["numeric_value"])
	assert.Equal(t, true, state["boolean_value"])

	// Check route state
	var routeState map[string]any
	err = json.Unmarshal(testState["route_state"], &routeState)
	require.NoError(t, err)

	routes := routeState["routes"].([]any)
	route1 := routes[0].(map[string]any)
	assert.NotEqual(t, "203.0.113.0/24", route1["network"])
	assert.Contains(t, route1["network"], "/24")
	assert.NotEqual(t, "203.0.113.1", route1["gateway"])
	domains := route1["domains"].([]any)
	assert.True(t, strings.HasSuffix(domains[0].(string), ".domain"))
	assert.True(t, strings.HasSuffix(domains[1].(string), ".domain"))

	// Check map keys are anonymized
	refCountMap := routeState["refCountMap"].(map[string]any)
	hasPublicIPKey := false
	hasIPv6Key := false
	hasPrivateIPKey := false
	for key := range refCountMap {
		if strings.Contains(key, "203.0.113.1") {
			hasPublicIPKey = true
		}
		if strings.Contains(key, "2001:db8::1") {
			hasIPv6Key = true
		}
		if key == "10.0.0.1/32" {
			hasPrivateIPKey = true
		}
	}
	assert.False(t, hasPublicIPKey, "public IP in key should be anonymized")
	assert.False(t, hasIPv6Key, "IPv6 in key should be anonymized")
	assert.True(t, hasPrivateIPKey, "private IP in key should remain unchanged")
}

func mustMarshal(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}
