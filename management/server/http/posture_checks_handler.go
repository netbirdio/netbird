package http

import (
	"encoding/json"
	"net/http"
	"net/netip"

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
	var (
		err error
		req api.PostureCheckUpdate
	)

	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
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
			util.WriteError(status.Errorf(status.PreconditionFailed, "Geo location database is not initialized. "+
				"Check the self-hosted Geo database documentation at https://docs.netbird.io/selfhosted/geo-support"), w)
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

	if processCheck := req.Checks.ProcessCheck; processCheck != nil {
		postureChecks.Checks.ProcessCheck = toProcessCheck(processCheck)
	}

	if err := p.accountManager.SavePostureChecks(account.Id, user.Id, &postureChecks); err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, toPostureChecksResponse(&postureChecks))
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

	if postureChecks.Checks.ProcessCheck != nil {
		checks.ProcessCheck = toProcessCheckResponse(postureChecks.Checks.ProcessCheck)
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
	for i, loc := range geoLocationCheck.Locations {
		var cityName *string
		if loc.CityName != "" {
			cityName = &geoLocationCheck.Locations[i].CityName
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

func toProcessCheckResponse(check *posture.ProcessCheck) *api.ProcessCheck {
	processes := make([]api.Process, 0, len(check.Processes))
	for i := range check.Processes {
		processes = append(processes, api.Process{
			Path:        &check.Processes[i].Path,
			WindowsPath: &check.Processes[i].WindowsPath,
		})
	}

	return &api.ProcessCheck{
		Processes: processes,
	}
}

func toProcessCheck(check *api.ProcessCheck) *posture.ProcessCheck {
	processes := make([]posture.Process, 0, len(check.Processes))
	for _, process := range check.Processes {
		var p posture.Process
		if process.Path != nil {
			p.Path = *process.Path
		}
		if process.WindowsPath != nil {
			p.WindowsPath = *process.WindowsPath
		}

		processes = append(processes, p)
	}

	return &posture.ProcessCheck{
		Processes: processes,
	}
}
