package networkmapdb

import (
	"testing"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
)

// disabled network resource shouldn't be in the resulting map
func TestBuildResourcePolicies_DisabledNetworkResource(t *testing.T) {
	networkResources := []nmdata.NetworkResource{
		{ID: "net-res-1", Enabled: false},
	}
	policies := []nmdata.Policy{
		{ID: "policy-1", Enabled: true},
	}
	resourceToGroupIdx := map[string]map[string]any{}
	policyToDestinationResourceIdx := map[string]map[string]any{
		"policy-1": {
			"net-res-1": struct{}{},
			"net-res-3": struct{}{},
		},
	}
	policyToDestinationGroupIdx := map[string]map[string]any{}

	assert.Empty(t, buildResourcePolicies(
		networkResources, policies, resourceToGroupIdx, policyToDestinationResourceIdx, policyToDestinationGroupIdx))
}

// disabled policy shouldn't be in the resulting map
func TestBuildResourcePolicies_DisabledPolicy(t *testing.T) {
	networkResources := []nmdata.NetworkResource{
		{ID: "net-res-1", Enabled: true},
	}
	policies := []nmdata.Policy{
		{ID: "policy-1", Enabled: false},
	}
	resourceToGroupIdx := map[string]map[string]any{}
	policyToDestinationResourceIdx := map[string]map[string]any{
		"policy-1": {
			"net-res-1": struct{}{},
			"net-res-3": struct{}{},
		},
	}
	policyToDestinationGroupIdx := map[string]map[string]any{}

	assert.Empty(t, buildResourcePolicies(
		networkResources, policies, resourceToGroupIdx, policyToDestinationResourceIdx, policyToDestinationGroupIdx))
}

// build ResourcePolicies via PolicyToDestinationResourceIdx only
func TestBuildResourcePolicies_ViaPolicyToDestinationResourceIdx(t *testing.T) {
	networkResources := []nmdata.NetworkResource{
		{ID: "net-res-1", Enabled: true},
		{ID: "net-res-2", Enabled: true},
		{ID: "net-res-3", Enabled: true},
	}
	policies := []nmdata.Policy{
		{ID: "policy-1", Enabled: true},
		{ID: "policy-2", Enabled: true},
		{ID: "policy-3", Enabled: true},
	}
	resourceToGroupIdx := map[string]map[string]any{}
	policyToDestinationResourceIdx := map[string]map[string]any{
		"policy-1": {
			"net-res-1": struct{}{},
			"net-res-3": struct{}{},
		},
		"policy-2": {
			"net-res-2": struct{}{},
		},
		"policy-3": {
			"net-res-1": struct{}{},
			"net-res-2": struct{}{},
		},
	}
	policyToDestinationGroupIdx := map[string]map[string]any{}

	resourceToPolicies := buildResourcePolicies(
		networkResources, policies, resourceToGroupIdx, policyToDestinationResourceIdx, policyToDestinationGroupIdx)

	assert.Equal(t, map[string][]*nmdata.Policy{
		"net-res-1": {
			{ID: "policy-1", Enabled: true},
			{ID: "policy-3", Enabled: true},
		},
		"net-res-2": {
			{ID: "policy-2", Enabled: true},
			{ID: "policy-3", Enabled: true},
		},
		"net-res-3": {
			{ID: "policy-1", Enabled: true},
		},
	}, resourceToPolicies)
}

// build ResourcePolicies via PolicyToDestinationGroupIdx only
func TestBuildResourcePolicies_ViaPolicyToDestinationGroupIdx(t *testing.T) {
	networkResources := []nmdata.NetworkResource{
		{ID: "net-res-1", Enabled: true},
		{ID: "net-res-2", Enabled: true},
		{ID: "net-res-3", Enabled: true},
	}
	policies := []nmdata.Policy{
		{ID: "policy-1", Enabled: true},
		{ID: "policy-2", Enabled: true},
		{ID: "policy-3", Enabled: true},
	}
	resourceToGroupIdx := map[string]map[string]any{
		"net-res-1": {
			"group-1": struct{}{},
			"group-2": struct{}{},
		},
		"net-res-2": {
			"group-2": struct{}{},
			"group-3": struct{}{},
		},
		"net-res-3": {
			"group-3": struct{}{},
			"group-4": struct{}{},
		},
	}
	policyToDestinationResourceIdx := map[string]map[string]any{}
	policyToDestinationGroupIdx := map[string]map[string]any{
		"policy-1": {
			"group-1": struct{}{},
			"group-2": struct{}{},
		},
		"policy-2": {
			"group-1": struct{}{},
			"group-4": struct{}{},
		},
		"policy-3": {
			"group-1": struct{}{},
			"group-3": struct{}{},
		},
	}

	resourceToPolicies := buildResourcePolicies(
		networkResources, policies, resourceToGroupIdx, policyToDestinationResourceIdx, policyToDestinationGroupIdx)

	assert.Equal(t, map[string][]*nmdata.Policy{
		"net-res-1": {
			{ID: "policy-1", Enabled: true},
			{ID: "policy-2", Enabled: true},
			{ID: "policy-3", Enabled: true},
		},
		"net-res-2": {
			{ID: "policy-1", Enabled: true},
			{ID: "policy-3", Enabled: true},
		},
		"net-res-3": {
			{ID: "policy-2", Enabled: true},
			{ID: "policy-3", Enabled: true},
		},
	}, resourceToPolicies)
}
