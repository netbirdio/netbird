package http

import (
	"encoding/json"
	"net/http"
	"regexp"
	"slices"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/status"
)

var (
	countryCodeRegex = regexp.MustCompile("^[a-zA-Z]{2}$")
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
		postureChecks = append(postureChecks, postureCheck.ToAPIResponse())
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

	postureChecksIdx := -1
	for i, postureCheck := range account.PostureChecks {
		if postureCheck.ID == postureChecksID {
			postureChecksIdx = i
			break
		}
	}
	if postureChecksIdx < 0 {
		util.WriteError(status.Errorf(status.NotFound, "couldn't find posture checks id %s", postureChecksID), w)
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

	util.WriteJSONObject(w, postureChecks.ToAPIResponse())
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

	if geoLocationCheck := req.Checks.GeoLocationCheck; geoLocationCheck != nil {
		if p.geolocationManager == nil {
			// TODO: update error message to include geo db self hosted doc link when ready
			util.WriteError(status.Errorf(status.PreconditionFailed, "Geo location database is not initialized"), w)
			return
		}
	}

	postureChecks, err := posture.NewChecksFromAPIPostureCheckUpdate(req, postureChecksID)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	if err := p.accountManager.SavePostureChecks(account.Id, user.Id, postureChecks); err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, postureChecks.ToAPIResponse())
}

func validatePostureChecksUpdate(req api.PostureCheckUpdate) error {
	if req.Name == "" {
		return status.Errorf(status.InvalidArgument, "posture checks name shouldn't be empty")
	}

	if req.Checks == nil || (req.Checks.NbVersionCheck == nil && req.Checks.OsVersionCheck == nil &&
		req.Checks.GeoLocationCheck == nil && req.Checks.PeerNetworkRangeCheck == nil) {
		return status.Errorf(status.InvalidArgument, "posture checks shouldn't be empty")
	}

	if req.Checks.NbVersionCheck != nil && req.Checks.NbVersionCheck.MinVersion == "" {
		return status.Errorf(status.InvalidArgument, "minimum version for NetBird's version check shouldn't be empty")
	}

	if osVersionCheck := req.Checks.OsVersionCheck; osVersionCheck != nil {
		emptyOS := osVersionCheck.Android == nil && osVersionCheck.Darwin == nil && osVersionCheck.Ios == nil &&
			osVersionCheck.Linux == nil && osVersionCheck.Windows == nil
		emptyMinVersion := osVersionCheck.Android != nil && osVersionCheck.Android.MinVersion == "" ||
			osVersionCheck.Darwin != nil && osVersionCheck.Darwin.MinVersion == "" ||
			osVersionCheck.Ios != nil && osVersionCheck.Ios.MinVersion == "" ||
			osVersionCheck.Linux != nil && osVersionCheck.Linux.MinKernelVersion == "" ||
			osVersionCheck.Windows != nil && osVersionCheck.Windows.MinKernelVersion == ""
		if emptyOS || emptyMinVersion {
			return status.Errorf(status.InvalidArgument,
				"minimum version for at least one OS in the OS version check shouldn't be empty")
		}
	}

	if geoLocationCheck := req.Checks.GeoLocationCheck; geoLocationCheck != nil {
		if geoLocationCheck.Action == "" {
			return status.Errorf(status.InvalidArgument, "action for geolocation check shouldn't be empty")
		}
		allowedActions := []api.GeoLocationCheckAction{api.GeoLocationCheckActionAllow, api.GeoLocationCheckActionDeny}
		if !slices.Contains(allowedActions, geoLocationCheck.Action) {
			return status.Errorf(status.InvalidArgument, "action for geolocation check is not valid value")
		}
		if len(geoLocationCheck.Locations) == 0 {
			return status.Errorf(status.InvalidArgument, "locations for geolocation check shouldn't be empty")
		}
		for _, loc := range geoLocationCheck.Locations {
			if loc.CountryCode == "" {
				return status.Errorf(status.InvalidArgument, "country code for geolocation check shouldn't be empty")
			}
			if !countryCodeRegex.MatchString(loc.CountryCode) {
				return status.Errorf(status.InvalidArgument, "country code must be 2 letters (ISO 3166-1 alpha-2 format)")
			}
		}
	}

	if peerNetworkRangeCheck := req.Checks.PeerNetworkRangeCheck; peerNetworkRangeCheck != nil {
		if peerNetworkRangeCheck.Action == "" {
			return status.Errorf(status.InvalidArgument, "action for peer network range check shouldn't be empty")
		}

		allowedActions := []api.PeerNetworkRangeCheckAction{api.PeerNetworkRangeCheckActionAllow, api.PeerNetworkRangeCheckActionDeny}
		if !slices.Contains(allowedActions, peerNetworkRangeCheck.Action) {
			return status.Errorf(status.InvalidArgument, "action for peer network range check is not valid value")
		}
		if len(peerNetworkRangeCheck.Ranges) == 0 {
			return status.Errorf(status.InvalidArgument, "network ranges for peer network range check shouldn't be empty")
		}
	}

	return nil
}
