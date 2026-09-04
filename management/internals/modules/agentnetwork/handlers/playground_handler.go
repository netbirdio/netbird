package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

func (h *handler) executePlayground(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var body api.AgentNetworkPlaygroundRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		util.WriteErrorResponse("invalid json", http.StatusBadRequest, w)
		return
	}

	headers := make([]proxy.AgentNetworkPlaygroundHeader, 0, len(body.Headers))
	for _, header := range body.Headers {
		headers = append(headers, proxy.AgentNetworkPlaygroundHeader{
			Name:   header.Name,
			Values: append([]string(nil), header.Values...),
		})
	}
	result, err := h.manager.ExecutePlayground(
		r.Context(),
		userAuth.AccountId,
		userAuth.UserId,
		agentnetwork.PlaygroundRequest{
			Principal: agentnetwork.PlaygroundPrincipal{
				Kind: proxy.PlaygroundPrincipalKind(body.Principal.Kind),
				ID:   body.Principal.Id,
			},
			Method:  string(body.Method),
			Path:    body.Path,
			Headers: headers,
			Body:    []byte(body.Body),
		},
	)
	if err != nil {
		writePlaygroundError(r, w, err)
		return
	}

	responseHeaders := make([]api.AgentNetworkPlaygroundHeader, 0, len(result.Headers))
	for _, header := range result.Headers {
		responseHeaders = append(responseHeaders, api.AgentNetworkPlaygroundHeader{
			Name:   header.Name,
			Values: append([]string{}, header.Values...),
		})
	}

	responseBody := string(result.Body)
	bodyEncoding := api.AgentNetworkPlaygroundResponseBodyEncodingUtf8
	if !utf8.Valid(result.Body) {
		responseBody = base64.StdEncoding.EncodeToString(result.Body)
		bodyEncoding = api.AgentNetworkPlaygroundResponseBodyEncodingBase64
	}
	util.WriteJSONObject(r.Context(), w, api.AgentNetworkPlaygroundResponse{
		StatusCode:    result.StatusCode,
		Headers:       responseHeaders,
		Body:          responseBody,
		BodyEncoding:  bodyEncoding,
		BodyTruncated: result.BodyTruncated,
		Identity: api.AgentNetworkPlaygroundIdentity{
			UserId:     result.UserID,
			UserEmail:  result.UserEmail,
			GroupIds:   append([]string{}, result.GroupIDs...),
			GroupNames: append([]string{}, result.GroupNames...),
		},
		Policy: api.AgentNetworkPlaygroundPolicy{
			Decision:            result.PolicyDecision,
			Reason:              result.PolicyReason,
			ProviderSurface:     result.ProviderSurface,
			Model:               result.Model,
			ResolvedProviderId:  result.ResolvedProviderID,
			AuthorisingGroupIds: append([]string{}, result.AuthorisingGroupIDs...),
			SelectedPolicyId:    result.SelectedPolicyID,
			AttributionGroupId:  result.AttributionGroupID,
		},
	})
}

func writePlaygroundError(r *http.Request, w http.ResponseWriter, err error) {
	if r.Context().Err() != nil {
		return
	}
	switch grpcstatus.Code(err) {
	case codes.Unavailable:
		util.WriteErrorResponse(grpcstatus.Convert(err).Message(), http.StatusServiceUnavailable, w)
	case codes.DeadlineExceeded:
		util.WriteErrorResponse("playground request timed out", http.StatusGatewayTimeout, w)
	case codes.DataLoss:
		util.WriteErrorResponse("invalid response from playground proxy", http.StatusBadGateway, w)
	default:
		util.WriteError(r.Context(), err, w)
	}
}
