package policies

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// handler is a handler that returns policy of the account
type handler struct {
	accountManager account.Manager
}

func AddEndpoints(accountManager account.Manager, locationManager geolocation.Geolocation, router *mux.Router) {
	policiesHandler := newHandler(accountManager)
	router.HandleFunc("/policies", policiesHandler.getAllPolicies).Methods("GET", "OPTIONS")
	router.HandleFunc("/policies", policiesHandler.createPolicy).Methods("POST", "OPTIONS")
	router.HandleFunc("/policies/{policyId}", policiesHandler.updatePolicy).Methods("PUT", "OPTIONS")
	router.HandleFunc("/policies/{policyId}", policiesHandler.getPolicy).Methods("GET", "OPTIONS")
	router.HandleFunc("/policies/{policyId}", policiesHandler.deletePolicy).Methods("DELETE", "OPTIONS")
}

// newHandler creates a new policies handler
func newHandler(accountManager account.Manager) *handler {
	return &handler{
		accountManager: accountManager,
	}
}

// getAllPolicies list for the account
func (h *handler) getAllPolicies(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	listPolicies, err := h.accountManager.ListPolicies(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	allGroups, err := h.accountManager.GetAllGroups(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	policies := make([]*api.Policy, 0, len(listPolicies))
	for _, policy := range listPolicies {
		resp := toPolicyResponse(allGroups, policy)
		if len(resp.Rules) == 0 {
			util.WriteError(r.Context(), status.Errorf(status.Internal, "no rules in the policy"), w)
			return
		}
		policies = append(policies, resp)
	}

	util.WriteJSONObject(r.Context(), w, policies)
}

// updatePolicy handles update to a policy identified by a given ID
func (h *handler) updatePolicy(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	vars := mux.Vars(r)
	policyID := vars["policyId"]
	if len(policyID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid policy ID"), w)
		return
	}

	_, err = h.accountManager.GetPolicy(r.Context(), accountID, policyID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	h.savePolicy(w, r, accountID, userID, policyID, false)
}

// createPolicy handles policy creation request
func (h *handler) createPolicy(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	h.savePolicy(w, r, accountID, userID, "", true)
}

// savePolicy handles policy creation and update
func (h *handler) savePolicy(w http.ResponseWriter, r *http.Request, accountID string, userID string, policyID string, create bool) {
	var req api.PutApiPoliciesPolicyIdJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if req.Name == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "policy name shouldn't be empty"), w)
		return
	}

	if len(req.Rules) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "policy rules shouldn't be empty"), w)
		return
	}

	description := ""
	if req.Description != nil {
		description = *req.Description
	}

	policy := &types.Policy{
		ID:          policyID,
		AccountID:   accountID,
		Name:        req.Name,
		Enabled:     req.Enabled,
		Description: description,
	}
	for _, rule := range req.Rules {
		var ruleID string
		if rule.Id != nil && policyID != "" {
			ruleID = *rule.Id
		}

		hasSources := rule.Sources != nil
		hasSourceResource := rule.SourceResource != nil

		hasDestinations := rule.Destinations != nil
		hasDestinationResource := rule.DestinationResource != nil

		if hasSources && hasSourceResource {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "specify either sources or  source resources, not both"), w)
			return
		}

		if hasDestinations && hasDestinationResource {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "specify either destinations or  destination resources, not both"), w)
			return
		}

		if !(hasSources || hasSourceResource) || !(hasDestinations || hasDestinationResource) {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "specify either sources or source resources and destinations or destination resources"), w)
			return
		}

		pr := types.PolicyRule{
			ID:            ruleID,
			PolicyID:      policyID,
			Name:          rule.Name,
			Bidirectional: rule.Bidirectional,
		}

		if hasSources {
			pr.Sources = *rule.Sources
		}

		if hasSourceResource {
			// TODO: validate the resource id and type
			sourceResource := &types.Resource{}
			sourceResource.FromAPIRequest(rule.SourceResource)
			pr.SourceResource = *sourceResource
		}

		if hasDestinations {
			pr.Destinations = *rule.Destinations
		}

		if hasDestinationResource {
			// TODO: validate the resource id and type
			destinationResource := &types.Resource{}
			destinationResource.FromAPIRequest(rule.DestinationResource)
			pr.DestinationResource = *destinationResource
		}

		pr.Enabled = rule.Enabled
		if rule.Description != nil {
			pr.Description = *rule.Description
		}

		switch rule.Action {
		case api.PolicyRuleUpdateActionAccept:
			pr.Action = types.PolicyTrafficActionAccept
		case api.PolicyRuleUpdateActionDrop:
			pr.Action = types.PolicyTrafficActionDrop
		default:
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "unknown action type"), w)
			return
		}

		switch rule.Protocol {
		case api.PolicyRuleUpdateProtocolAll:
			pr.Protocol = types.PolicyRuleProtocolALL
		case api.PolicyRuleUpdateProtocolTcp:
			pr.Protocol = types.PolicyRuleProtocolTCP
		case api.PolicyRuleUpdateProtocolUdp:
			pr.Protocol = types.PolicyRuleProtocolUDP
		case api.PolicyRuleUpdateProtocolIcmp:
			pr.Protocol = types.PolicyRuleProtocolICMP
		case api.PolicyRuleUpdateProtocolNetbirdSsh:
			pr.Protocol = types.PolicyRuleProtocolNetbirdSSH
		default:
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "unknown protocol type: %v", rule.Protocol), w)
			return
		}

		if (rule.Ports != nil && len(*rule.Ports) != 0) && (rule.PortRanges != nil && len(*rule.PortRanges) != 0) {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "specify either individual ports or port ranges, not both"), w)
			return
		}

		if rule.Ports != nil && len(*rule.Ports) != 0 {
			for _, v := range *rule.Ports {
				if port, err := strconv.Atoi(v); err != nil || port < 1 || port > 65535 {
					util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "valid port value is in 1..65535 range"), w)
					return
				}
				pr.Ports = append(pr.Ports, v)
			}
		}

		if rule.PortRanges != nil && len(*rule.PortRanges) != 0 {
			for _, portRange := range *rule.PortRanges {
				if portRange.Start < 1 || portRange.End > 65535 {
					util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "valid port value is in 1..65535 range"), w)
					return
				}
				pr.PortRanges = append(pr.PortRanges, types.RulePortRange{
					Start: uint16(portRange.Start),
					End:   uint16(portRange.End),
				})
			}
		}

		if pr.Protocol == types.PolicyRuleProtocolNetbirdSSH && rule.AuthorizedGroups != nil && len(*rule.AuthorizedGroups) != 0 {
			for _, sourceGroupID := range pr.Sources {
				_, ok := (*rule.AuthorizedGroups)[sourceGroupID]
				if !ok {
					util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "authorized group for netbird-ssh protocol should be specified for each source group"), w)
					return
				}
			}
			pr.AuthorizedGroups = *rule.AuthorizedGroups
		}

		// validate policy object
		if pr.Protocol == types.PolicyRuleProtocolALL || pr.Protocol == types.PolicyRuleProtocolICMP {
			if len(pr.Ports) != 0 || len(pr.PortRanges) != 0 {
				util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "for ALL or ICMP protocol ports is not allowed"), w)
				return
			}
		}
		policy.Rules = append(policy.Rules, &pr)
	}

	if req.SourcePostureChecks != nil {
		policy.SourcePostureChecks = *req.SourcePostureChecks
	}

	policy, err := h.accountManager.SavePolicy(r.Context(), accountID, userID, policy, create)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	allGroups, err := h.accountManager.GetAllGroups(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toPolicyResponse(allGroups, policy)
	if len(resp.Rules) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.Internal, "no rules in the policy"), w)
		return
	}

	util.WriteJSONObject(r.Context(), w, resp)
}

// deletePolicy handles policy deletion request
func (h *handler) deletePolicy(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId
	vars := mux.Vars(r)
	policyID := vars["policyId"]
	if len(policyID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid policy ID"), w)
		return
	}

	if err = h.accountManager.DeletePolicy(r.Context(), accountID, policyID, userID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

// getPolicy handles a group Get request identified by ID
func (h *handler) getPolicy(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	vars := mux.Vars(r)
	policyID := vars["policyId"]
	if len(policyID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid policy ID"), w)
		return
	}

	policy, err := h.accountManager.GetPolicy(r.Context(), accountID, policyID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	allGroups, err := h.accountManager.GetAllGroups(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toPolicyResponse(allGroups, policy)
	if len(resp.Rules) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.Internal, "no rules in the policy"), w)
		return
	}

	util.WriteJSONObject(r.Context(), w, resp)
}

func toPolicyResponse(groups []*types.Group, policy *types.Policy) *api.Policy {
	groupsMap := make(map[string]*types.Group)
	for _, group := range groups {
		groupsMap[group.ID] = group
	}

	cache := make(map[string]api.GroupMinimum)
	ap := &api.Policy{
		Id:                  &policy.ID,
		Name:                policy.Name,
		Description:         &policy.Description,
		Enabled:             policy.Enabled,
		SourcePostureChecks: policy.SourcePostureChecks,
	}
	for _, r := range policy.Rules {
		rID := r.ID
		rDescription := r.Description
		rule := api.PolicyRule{
			Id:                  &rID,
			Name:                r.Name,
			Enabled:             r.Enabled,
			Description:         &rDescription,
			Bidirectional:       r.Bidirectional,
			Protocol:            api.PolicyRuleProtocol(r.Protocol),
			Action:              api.PolicyRuleAction(r.Action),
			SourceResource:      r.SourceResource.ToAPIResponse(),
			DestinationResource: r.DestinationResource.ToAPIResponse(),
		}

		if len(r.AuthorizedGroups) != 0 {
			authorizedGroupsCopy := r.AuthorizedGroups
			rule.AuthorizedGroups = &authorizedGroupsCopy
		}

		if len(r.Ports) != 0 {
			portsCopy := r.Ports
			rule.Ports = &portsCopy
		}

		if len(r.PortRanges) != 0 {
			portRanges := make([]api.RulePortRange, 0, len(r.PortRanges))
			for _, portRange := range r.PortRanges {
				portRanges = append(portRanges, api.RulePortRange{
					End:   int(portRange.End),
					Start: int(portRange.Start),
				})
			}
			rule.PortRanges = &portRanges
		}

		var sources []api.GroupMinimum
		for _, gid := range r.Sources {
			_, ok := cache[gid]
			if ok {
				continue
			}

			if group, ok := groupsMap[gid]; ok {
				minimum := api.GroupMinimum{
					Id:         group.ID,
					Name:       group.Name,
					PeersCount: len(group.Peers),
				}
				sources = append(sources, minimum)
				cache[gid] = minimum
			}
		}
		rule.Sources = &sources

		var destinations []api.GroupMinimum
		for _, gid := range r.Destinations {
			cachedMinimum, ok := cache[gid]
			if ok {
				destinations = append(destinations, cachedMinimum)
				continue
			}
			if group, ok := groupsMap[gid]; ok {
				minimum := api.GroupMinimum{
					Id:             group.ID,
					Name:           group.Name,
					PeersCount:     len(group.Peers),
					ResourcesCount: len(group.Resources),
				}
				destinations = append(destinations, minimum)
				cache[gid] = minimum
			}
		}
		rule.Destinations = &destinations

		ap.Rules = append(ap.Rules, rule)
	}
	return ap
}
