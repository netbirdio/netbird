//go:build integration

package networkmap_pgsql

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
)

func TestGetPolicies(t *testing.T) {
	ctx := context.TODO()

	execQuery(t, ctx,
		`insert into policies (id, public_id, account_id, enabled, source_posture_checks)
		 values('policy-1','policy-1-public','account-1',true,'["posture-checks-1","posture-checks-2"]')`)
	execQuery(t, ctx,
		`insert into policy_rules (id, policy_id, enabled, action, protocol, bidirectional, sources, destinations,
		                           source_resource, destination_resource, ports, port_ranges,
								   authorized_groups, authorized_user)
		 values('policy-1-rule-1','policy-1',true,'accept','tcp',true,'["group-one-resource-id","group-two-resources-id"]','["group-one-resource-id","group-two-resources-id"]',
		        '{"ID":"host-id-1","Type":"host"}','{"ID":"domain-1","Type":"domain"}','["8080","8443"]', '[{"Start":8080,"End":8090}]',
				'{"group-one-resource-id":["user-1", "user-2"]}','user-3')`)
	execQuery(t, ctx,
		`insert into policies (id, public_id, account_id, enabled, source_posture_checks)
		 values('policy-2','policy-2-public','account-1',true,'["posture-checks-3","posture-checks-4"]')`)
	execQuery(t, ctx,
		`insert into policy_rules (id, policy_id, enabled, action, protocol, bidirectional, sources, destinations,
		                           source_resource, destination_resource, ports, port_ranges,
								   authorized_groups, authorized_user)
		 values('policy-2-rule-1','policy-2',true,'accept','tcp',true,'["group-one-resource-id"]','["group-two-resources-id"]',
		        '{"ID":"host-id-3","Type":"host"}','{"ID":"domain-3","Type":"domain"}','["8080","8443"]', '[{"Start":8080,"End":8090}]',
				'{"group-one-resource-id":["user-6", "user-7"]}','user-8')`)
	// policy with a rule with null fields
	execQuery(t, ctx,
		`insert into policies (id, public_id, account_id, enabled, source_posture_checks)
		 values('policy-3','policy-3-public','account-1',true,null)`)
	execQuery(t, ctx,
		`insert into policy_rules (id, policy_id, enabled, action, protocol, bidirectional, sources, destinations,
		                           source_resource, destination_resource, ports, port_ranges,
								   authorized_groups, authorized_user)
		 values('policy-3-rule-1','policy-3',true,null,null,null,null,null,null,null,null,null,null,null)`)
	// policy with a disabled rule, destination resource and groups should not be in indexes
	execQuery(t, ctx,
		`insert into policies (id, public_id, account_id, enabled, source_posture_checks)
		 values('policy-4','policy-4-public','account-1',true,null)`)
	execQuery(t, ctx,
		`insert into policy_rules (id, policy_id, enabled, action, protocol, bidirectional, sources, destinations,
		                           source_resource, destination_resource, ports, port_ranges,
								   authorized_groups, authorized_user)
		 values('policy-4-rule-1','policy-4',false,null,null,null,null,'["group-two-resources-id"]',
		        null,'{"ID":"domain-3","Type":"domain"}',null,null,null,null)`)

	policies, policyToDestinationResourceIdx, policyToDestinationGroupIdx, err := conn(t, ctx).GetPolicies(ctx, "account-1")
	assert.NoError(t, err)

	assert.Contains(t, policies, nmdata.Policy{
		ID:                  "policy-1",
		PublicID:            "policy-1-public",
		Enabled:             true,
		SourcePostureChecks: []string{"posture-checks-1", "posture-checks-2"},
		Rules: []*nmdata.PolicyRule{
			{
				ID:                  "policy-1",
				PolicyID:            "policy-1",
				Enabled:             true,
				Action:              "accept",
				Protocol:            "tcp",
				Bidirectional:       true,
				Sources:             []string{"group-one-resource-id", "group-two-resources-id"},
				Destinations:        []string{"group-one-resource-id", "group-two-resources-id"},
				SourceResource:      nmdata.Resource{ID: "host-id-1", Type: "host"},
				DestinationResource: nmdata.Resource{ID: "domain-1", Type: "domain"},
				Ports:               []string{"8080", "8443"},
				PortRanges:          []nmdata.RulePortRange{{Start: 8080, End: 8090}},
				AuthorizedGroups:    map[string][]string{"group-one-resource-id": {"user-1", "user-2"}},
				AuthorizedUser:      "user-3",
			},
		},
	})

	assert.Contains(t, policies, nmdata.Policy{
		ID:                  "policy-2",
		PublicID:            "policy-2-public",
		Enabled:             true,
		SourcePostureChecks: []string{"posture-checks-3", "posture-checks-4"},
		Rules: []*nmdata.PolicyRule{
			{
				ID:                  "policy-2",
				PolicyID:            "policy-2",
				Enabled:             true,
				Action:              "accept",
				Protocol:            "tcp",
				Bidirectional:       true,
				Sources:             []string{"group-one-resource-id"},
				Destinations:        []string{"group-two-resources-id"},
				SourceResource:      nmdata.Resource{ID: "host-id-3", Type: "host"},
				DestinationResource: nmdata.Resource{ID: "domain-3", Type: "domain"},
				Ports:               []string{"8080", "8443"},
				PortRanges:          []nmdata.RulePortRange{{Start: 8080, End: 8090}},
				AuthorizedGroups:    map[string][]string{"group-one-resource-id": {"user-6", "user-7"}},
				AuthorizedUser:      "user-8",
			},
		},
	})

	assert.Contains(t, policies, nmdata.Policy{
		ID:                  "policy-3",
		PublicID:            "policy-3-public",
		Enabled:             true,
		SourcePostureChecks: nil,
		Rules: []*nmdata.PolicyRule{
			{
				ID:       "policy-3",
				PolicyID: "policy-3",
				Enabled:  true,
			},
		},
	})
	assert.Contains(t, policies, nmdata.Policy{
		ID:                  "policy-4",
		PublicID:            "policy-4-public",
		Enabled:             true,
		SourcePostureChecks: nil,
		Rules: []*nmdata.PolicyRule{
			{
				ID:                  "policy-4",
				PolicyID:            "policy-4",
				Enabled:             false,
				Destinations:        []string{"group-two-resources-id"},
				DestinationResource: nmdata.Resource{ID: "domain-3", Type: "domain"},
			},
		},
	})

	assert.Equal(t, policyToDestinationGroupIdx, map[string]map[string]any{
		"policy-1": {"group-one-resource-id": struct{}{}, "group-two-resources-id": struct{}{}},
		"policy-2": {"group-two-resources-id": struct{}{}},
	})
	assert.Equal(t, policyToDestinationResourceIdx, map[string]map[string]any{
		"policy-1": {"domain-1": struct{}{}},
		"policy-2": {"domain-3": struct{}{}},
	})
}
