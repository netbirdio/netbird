package policies

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/geolocation"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/configs"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
)

// handler is a handler that returns policy of the account
type handler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

func AddEndpoints(accountManager server.AccountManager, locationManager *geolocation.Geolocation, authCfg configs.AuthCfg, router *mux.Router) {
	policiesHandler := newHandler(accountManager, authCfg)
	router.HandleFunc("/policies", policiesHandler.getAllPolicies).Methods("GET", "OPTIONS")
	router.HandleFunc("/policies", policiesHandler.createPolicy).Methods("POST", "OPTIONS")
	router.HandleFunc("/policies/{policyId}", policiesHandler.updatePolicy).Methods("PUT", "OPTIONS")
	router.HandleFunc("/policies/{policyId}", policiesHandler.getPolicy).Methods("GET", "OPTIONS")
	router.HandleFunc("/policies/{policyId}", policiesHandler.deletePolicy).Methods("DELETE", "OPTIONS")
	addPostureCheckEndpoint(accountManager, locationManager, authCfg, router)
}

// newHandler creates a new policies handler
func newHandler(accountManager server.AccountManager, authCfg configs.AuthCfg) *handler {
	return &handler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// getAllPolicies list for the account
func (h *handler) getAllPolicies(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

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
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

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

	h.savePolicy(w, r, accountID, userID, policyID)
}

// createPolicy handles policy creation request
func (h *handler) createPolicy(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	h.savePolicy(w, r, accountID, userID, "")
}

// savePolicy handles policy creation and update
func (h *handler) savePolicy(w http.ResponseWriter, r *http.Request, accountID string, userID string, policyID string) {
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

	policy := &server.Policy{
		ID:          policyID,
		AccountID:   accountID,
		Name:        req.Name,
		Enabled:     req.Enabled,
		Description: req.Description,
	}
	for _, rule := range req.Rules {
		var ruleID string
		if rule.Id != nil {
			ruleID = *rule.Id
		}

		pr := server.PolicyRule{
			ID:            ruleID,
			PolicyID:      policyID,
			Name:          rule.Name,
			Destinations:  rule.Destinations,
			Sources:       rule.Sources,
			Bidirectional: rule.Bidirectional,
		}

		pr.Enabled = rule.Enabled
		if rule.Description != nil {
			pr.Description = *rule.Description
		}

		switch rule.Action {
		case api.PolicyRuleUpdateActionAccept:
			pr.Action = server.PolicyTrafficActionAccept
		case api.PolicyRuleUpdateActionDrop:
			pr.Action = server.PolicyTrafficActionDrop
		default:
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "unknown action type"), w)
			return
		}

		switch rule.Protocol {
		case api.PolicyRuleUpdateProtocolAll:
			pr.Protocol = server.PolicyRuleProtocolALL
		case api.PolicyRuleUpdateProtocolTcp:
			pr.Protocol = server.PolicyRuleProtocolTCP
		case api.PolicyRuleUpdateProtocolUdp:
			pr.Protocol = server.PolicyRuleProtocolUDP
		case api.PolicyRuleUpdateProtocolIcmp:
			pr.Protocol = server.PolicyRuleProtocolICMP
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
				pr.PortRanges = append(pr.PortRanges, server.RulePortRange{
					Start: uint16(portRange.Start),
					End:   uint16(portRange.End),
				})
			}
		}

		// validate policy object
		switch pr.Protocol {
		case server.PolicyRuleProtocolALL, server.PolicyRuleProtocolICMP:
			if len(pr.Ports) != 0 || len(pr.PortRanges) != 0 {
				util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "for ALL or ICMP protocol ports is not allowed"), w)
				return
			}
			if !pr.Bidirectional {
				util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "for ALL or ICMP protocol type flow can be only bi-directional"), w)
				return
			}
		case server.PolicyRuleProtocolTCP, server.PolicyRuleProtocolUDP:
			if !pr.Bidirectional && (len(pr.Ports) == 0 || len(pr.PortRanges) != 0) {
				util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "for ALL or ICMP protocol type flow can be only bi-directional"), w)
				return
			}
		}

		policy.Rules = append(policy.Rules, &pr)
	}

	if req.SourcePostureChecks != nil {
		policy.SourcePostureChecks = *req.SourcePostureChecks
	}

	policy, err := h.accountManager.SavePolicy(r.Context(), accountID, userID, policy)
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
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

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
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

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

func toPolicyResponse(groups []*nbgroup.Group, policy *server.Policy) *api.Policy {
	groupsMap := make(map[string]*nbgroup.Group)
	for _, group := range groups {
		groupsMap[group.ID] = group
	}

	cache := make(map[string]api.GroupMinimum)
	ap := &api.Policy{
		Id:                  &policy.ID,
		Name:                policy.Name,
		Description:         policy.Description,
		Enabled:             policy.Enabled,
		SourcePostureChecks: policy.SourcePostureChecks,
	}
	for _, r := range policy.Rules {
		rID := r.ID
		rDescription := r.Description
		rule := api.PolicyRule{
			Id:            &rID,
			Name:          r.Name,
			Enabled:       r.Enabled,
			Description:   &rDescription,
			Bidirectional: r.Bidirectional,
			Protocol:      api.PolicyRuleProtocol(r.Protocol),
			Action:        api.PolicyRuleAction(r.Action),
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
				rule.Sources = append(rule.Sources, minimum)
				cache[gid] = minimum
			}
		}

		for _, gid := range r.Destinations {
			cachedMinimum, ok := cache[gid]
			if ok {
				rule.Destinations = append(rule.Destinations, cachedMinimum)
				continue
			}
			if group, ok := groupsMap[gid]; ok {
				minimum := api.GroupMinimum{
					Id:         group.ID,
					Name:       group.Name,
					PeersCount: len(group.Peers),
				}
				rule.Destinations = append(rule.Destinations, minimum)
				cache[gid] = minimum
			}
		}
		ap.Rules = append(ap.Rules, rule)
	}
	return ap
}
