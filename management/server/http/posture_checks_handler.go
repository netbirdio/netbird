package http

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"regexp"
	"slices"

	"github.com/gorilla/mux"
	"github.com/rs/xid"

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
	}

	if nbVersionCheck := req.Checks.NbVersionCheck; nbVersionCheck != nil {
		postureChecks.Checks.NBVersionCheck = &posture.NBVersionCheck{
			MinVersion: nbVersionCheck.MinVersion,
		}
	}

	if osVersionCheck := req.Checks.OsVersionCheck; osVersionCheck != nil {
		postureChecks.Checks.OSVersionCheck = &posture.OSVersionCheck{
			Android: (*posture.MinVersionCheck)(osVersionCheck.Android),
			Darwin:  (*posture.MinVersionCheck)(osVersionCheck.Darwin),
			Ios:     (*posture.MinVersionCheck)(osVersionCheck.Ios),
			Linux:   (*posture.MinKernelVersionCheck)(osVersionCheck.Linux),
			Windows: (*posture.MinKernelVersionCheck)(osVersionCheck.Windows),
		}
	}

	if geoLocationCheck := req.Checks.GeoLocationCheck; geoLocationCheck != nil {
		if p.geolocationManager == nil {
			// TODO: update error message to include geo db self hosted doc link when ready
			util.WriteError(status.Errorf(status.PreconditionFailed, "Geo location database is not initialized"), w)
			return
		}
		postureChecks.Checks.GeoLocationCheck = toPostureGeoLocationCheck(geoLocationCheck)
	}

	if peerNetworkRangeCheck := req.Checks.PeerNetworkRangeCheck; peerNetworkRangeCheck != nil {
		postureChecks.Checks.PeerNetworkRangeCheck, err = toPeerNetworkRangeCheck(peerNetworkRangeCheck)
		if err != nil {
			util.WriteError(status.Errorf(status.InvalidArgument, "invalid network prefix"), w)
			return
		}
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

func toPostureChecksResponse(postureChecks *posture.Checks) *api.PostureCheck {
	var checks api.Checks

	if postureChecks.Checks.NBVersionCheck != nil {
		checks.NbVersionCheck = &api.NBVersionCheck{
			MinVersion: postureChecks.Checks.NBVersionCheck.MinVersion,
		}
	}

	if postureChecks.Checks.OSVersionCheck != nil {
		checks.OsVersionCheck = &api.OSVersionCheck{
			Android: (*api.MinVersionCheck)(postureChecks.Checks.OSVersionCheck.Android),
			Darwin:  (*api.MinVersionCheck)(postureChecks.Checks.OSVersionCheck.Darwin),
			Ios:     (*api.MinVersionCheck)(postureChecks.Checks.OSVersionCheck.Ios),
			Linux:   (*api.MinKernelVersionCheck)(postureChecks.Checks.OSVersionCheck.Linux),
			Windows: (*api.MinKernelVersionCheck)(postureChecks.Checks.OSVersionCheck.Windows),
		}
	}

	if postureChecks.Checks.GeoLocationCheck != nil {
		checks.GeoLocationCheck = toGeoLocationCheckResponse(postureChecks.Checks.GeoLocationCheck)
	}

	if postureChecks.Checks.PeerNetworkRangeCheck != nil {
		checks.PeerNetworkRangeCheck = toPeerNetworkRangeCheckResponse(postureChecks.Checks.PeerNetworkRangeCheck)
	}

	return &api.PostureCheck{
		Id:          postureChecks.ID,
		Name:        postureChecks.Name,
		Description: &postureChecks.Description,
		Checks:      checks,
	}
}

func toGeoLocationCheckResponse(geoLocationCheck *posture.GeoLocationCheck) *api.GeoLocationCheck {
	locations := make([]api.Location, 0, len(geoLocationCheck.Locations))
	for _, loc := range geoLocationCheck.Locations {
		l := loc // make G601 happy
		var cityName *string
		if loc.CityName != "" {
			cityName = &l.CityName
		}
		locations = append(locations, api.Location{
			CityName:    cityName,
			CountryCode: loc.CountryCode,
		})
	}

	return &api.GeoLocationCheck{
		Action:    api.GeoLocationCheckAction(geoLocationCheck.Action),
		Locations: locations,
	}
}

func toPostureGeoLocationCheck(apiGeoLocationCheck *api.GeoLocationCheck) *posture.GeoLocationCheck {
	locations := make([]posture.Location, 0, len(apiGeoLocationCheck.Locations))
	for _, loc := range apiGeoLocationCheck.Locations {
		cityName := ""
		if loc.CityName != nil {
			cityName = *loc.CityName
		}
		locations = append(locations, posture.Location{
			CountryCode: loc.CountryCode,
			CityName:    cityName,
		})
	}

	return &posture.GeoLocationCheck{
		Action:    string(apiGeoLocationCheck.Action),
		Locations: locations,
	}
}

func toPeerNetworkRangeCheckResponse(check *posture.PeerNetworkRangeCheck) *api.PeerNetworkRangeCheck {
	netPrefixes := make([]string, 0, len(check.Ranges))
	for _, netPrefix := range check.Ranges {
		netPrefixes = append(netPrefixes, netPrefix.String())
	}

	return &api.PeerNetworkRangeCheck{
		Ranges: netPrefixes,
		Action: api.PeerNetworkRangeCheckAction(check.Action),
	}
}

func toPeerNetworkRangeCheck(check *api.PeerNetworkRangeCheck) (*posture.PeerNetworkRangeCheck, error) {
	prefixes := make([]netip.Prefix, 0)
	for _, prefix := range check.Ranges {
		parsedPrefix, err := netip.ParsePrefix(prefix)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, parsedPrefix)
	}

	return &posture.PeerNetworkRangeCheck{
		Ranges: prefixes,
		Action: string(check.Action),
	}, nil
}
