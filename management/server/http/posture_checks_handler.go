package http

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/status"
)

// PostureChecksHandler is a handler that returns posture checks of the account.
type PostureChecksHandler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewPostureChecksHandler creates a new PostureChecks handler
func NewPostureChecksHandler(accountManager server.AccountManager, authCfg AuthCfg) *PostureChecksHandler {
	return &PostureChecksHandler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// GetAllPostureChecks list for the account
func (p *PostureChecksHandler) GetAllPostureChecks(w http.ResponseWriter, r *http.Request) {
	claims := p.claimsExtractor.FromRequestContext(r)
	account, user, err := p.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	accountPostureChecks, err := p.accountManager.ListPostureChecks(account.Id, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	postureChecks := []*api.PostureCheck{}
	for _, postureCheck := range accountPostureChecks {
		postureChecks = append(postureChecks, toPostureChecksResponse(postureCheck))
	}

	util.WriteJSONObject(w, postureChecks)
}

// UpdatePostureCheck handles update to a posture check identified by a given ID
func (p *PostureChecksHandler) UpdatePostureCheck(w http.ResponseWriter, r *http.Request) {
	claims := p.claimsExtractor.FromRequestContext(r)
	account, user, err := p.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	postureChecksID := vars["postureCheckId"]
	if len(postureChecksID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid posture checks ID"), w)
		return
	}

	p.savePostureChecks(w, r, account, user, postureChecksID)
}

// CreatePostureCheck handles posture check creation request
func (p *PostureChecksHandler) CreatePostureCheck(w http.ResponseWriter, r *http.Request) {
	claims := p.claimsExtractor.FromRequestContext(r)
	account, user, err := p.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	p.savePostureChecks(w, r, account, user, "")
}

// GetPostureCheck handles a posture check Get request identified by ID
func (p *PostureChecksHandler) GetPostureCheck(w http.ResponseWriter, r *http.Request) {
	claims := p.claimsExtractor.FromRequestContext(r)
	account, user, err := p.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	postureChecksID := vars["postureCheckId"]
	if len(postureChecksID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid posture checks ID"), w)
		return
	}

	postureChecks, err := p.accountManager.GetPostureChecks(account.Id, postureChecksID, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, toPostureChecksResponse(postureChecks))
}

// DeletePostureCheck handles posture check deletion request
func (p *PostureChecksHandler) DeletePostureCheck(w http.ResponseWriter, r *http.Request) {
	claims := p.claimsExtractor.FromRequestContext(r)
	account, user, err := p.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	postureChecksID := vars["postureCheckId"]
	if len(postureChecksID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid posture checks ID"), w)
		return
	}

	if err = p.accountManager.DeletePostureChecks(account.Id, postureChecksID, user.Id); err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, emptyObject{})
}

// savePostureChecks handles posture checks create and update
func (p *PostureChecksHandler) savePostureChecks(
	w http.ResponseWriter,
	r *http.Request,
	account *server.Account,
	user *server.User,
	postureChecksID string,
) {

	var req api.PostureCheckUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	err := validatePostureChecksUpdate(req)
	if err != nil {
		util.WriteErrorResponse(err.Error(), http.StatusBadRequest, w)
		return
	}

	if postureChecksID == "" {
		postureChecksID = xid.New().String()
	}

	postureChecks := posture.Checks{
		ID:          postureChecksID,
		Name:        req.Name,
		Description: req.Description,
		Checks:      make([]posture.Check, 0),
	}

	if nbVersionCheck := req.Checks.NbVersionCheck; nbVersionCheck != nil {
		var maxVersion string
		if nbVersionCheck.MaxVersion != nil {
			maxVersion = *nbVersionCheck.MaxVersion
		}

		postureChecks.Checks = append(postureChecks.Checks, &posture.NBVersionCheck{
			Enabled:    nbVersionCheck.Enabled,
			MinVersion: nbVersionCheck.MinVersion,
			MaxVersion: maxVersion,
		})
	}

	if err := p.accountManager.SavePostureChecks(account.Id, user.Id, &postureChecks); err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, toPostureChecksResponse(&postureChecks))
}

func validatePostureChecksUpdate(req api.PostureCheckUpdate) error {
	if req.Name == "" {
		return status.Errorf(status.InvalidArgument, "posture checks name shouldn't be empty")
	}

	if req.Checks == nil {
		return status.Errorf(status.InvalidArgument, "posture checks shouldn't be empty")
	}

	if req.Checks.NbVersionCheck != nil && req.Checks.NbVersionCheck.MinVersion == "" {
		return status.Errorf(status.InvalidArgument, "minimum version for NetBird's version check shouldn't be empty")
	}

	return nil
}

func toPostureChecksResponse(postureChecks *posture.Checks) *api.PostureCheck {
	var checks api.Checks
	for _, check := range postureChecks.Checks {
		switch check.Name() {
		case posture.NBVersionCheckName:
			versionCheck := check.(*posture.NBVersionCheck)
			checks.NbVersionCheck = &api.NBVersionCheck{
				Enabled:    versionCheck.Enabled,
				MinVersion: versionCheck.MinVersion,
				MaxVersion: &versionCheck.MaxVersion,
			}
		}
	}

	return &api.PostureCheck{
		Id:          postureChecks.ID,
		Name:        postureChecks.Name,
		Description: &postureChecks.Description,
		Checks:      &checks,
	}
}
