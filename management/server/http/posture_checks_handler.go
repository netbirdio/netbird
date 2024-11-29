package http

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/status"
)

// PostureChecksHandler is a handler that returns posture checks of the account.
type PostureChecksHandler struct {
	accountManager     server.AccountManager
	geolocationManager *geolocation.Geolocation
	claimsExtractor    *jwtclaims.ClaimsExtractor
}

// NewPostureChecksHandler creates a new PostureChecks handler
func NewPostureChecksHandler(accountManager server.AccountManager, geolocationManager *geolocation.Geolocation, authCfg AuthCfg) *PostureChecksHandler {
	return &PostureChecksHandler{
		accountManager:     accountManager,
		geolocationManager: geolocationManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// GetAllPostureChecks list for the account
func (p *PostureChecksHandler) GetAllPostureChecks(w http.ResponseWriter, r *http.Request) {
	claims := p.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := p.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	listPostureChecks, err := p.accountManager.ListPostureChecks(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	postureChecks := make([]*api.PostureCheck, 0, len(listPostureChecks))
	for _, postureCheck := range listPostureChecks {
		postureChecks = append(postureChecks, postureCheck.ToAPIResponse())
	}

	util.WriteJSONObject(r.Context(), w, postureChecks)
}

// UpdatePostureCheck handles update to a posture check identified by a given ID
func (p *PostureChecksHandler) UpdatePostureCheck(w http.ResponseWriter, r *http.Request) {
	claims := p.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := p.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	postureChecksID := vars["postureCheckId"]
	if len(postureChecksID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid posture checks ID"), w)
		return
	}

	_, err = p.accountManager.GetPostureChecks(r.Context(), accountID, postureChecksID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	p.savePostureChecks(w, r, accountID, userID, postureChecksID)
}

// CreatePostureCheck handles posture check creation request
func (p *PostureChecksHandler) CreatePostureCheck(w http.ResponseWriter, r *http.Request) {
	claims := p.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := p.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	p.savePostureChecks(w, r, accountID, userID, "")
}

// GetPostureCheck handles a posture check Get request identified by ID
func (p *PostureChecksHandler) GetPostureCheck(w http.ResponseWriter, r *http.Request) {
	claims := p.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := p.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	postureChecksID := vars["postureCheckId"]
	if len(postureChecksID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid posture checks ID"), w)
		return
	}

	postureChecks, err := p.accountManager.GetPostureChecks(r.Context(), accountID, postureChecksID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, postureChecks.ToAPIResponse())
}

// DeletePostureCheck handles posture check deletion request
func (p *PostureChecksHandler) DeletePostureCheck(w http.ResponseWriter, r *http.Request) {
	claims := p.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := p.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	postureChecksID := vars["postureCheckId"]
	if len(postureChecksID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid posture checks ID"), w)
		return
	}

	if err = p.accountManager.DeletePostureChecks(r.Context(), accountID, postureChecksID, userID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, emptyObject{})
}

// savePostureChecks handles posture checks create and update
func (p *PostureChecksHandler) savePostureChecks(w http.ResponseWriter, r *http.Request, accountID, userID, postureChecksID string) {
	var (
		err error
		req api.PostureCheckUpdate
	)

	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if geoLocationCheck := req.Checks.GeoLocationCheck; geoLocationCheck != nil {
		if p.geolocationManager == nil {
			util.WriteError(r.Context(), status.Errorf(status.PreconditionFailed, "Geo location database is not initialized. "+
				"Check the self-hosted Geo database documentation at https://docs.netbird.io/selfhosted/geo-support"), w)
			return
		}
	}

	postureChecks, err := posture.NewChecksFromAPIPostureCheckUpdate(req, postureChecksID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	postureChecks, err = p.accountManager.SavePostureChecks(r.Context(), accountID, userID, postureChecks)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, postureChecks.ToAPIResponse())
}
