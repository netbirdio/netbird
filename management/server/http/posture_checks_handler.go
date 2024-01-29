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
		Checks:      make([]posture.Check, 0),
	}

	if nbVersionCheck := req.Checks.NbVersionCheck; nbVersionCheck != nil {
		postureChecks.Checks = append(postureChecks.Checks, &posture.NBVersionCheck{
			MinVersion: nbVersionCheck.MinVersion,
		})
	}

	if osVersionCheck := req.Checks.OsVersionCheck; osVersionCheck != nil {
		postureChecks.Checks = append(postureChecks.Checks, &posture.OSVersionCheck{
			Android: (*posture.MinVersionCheck)(osVersionCheck.Android),
			Darwin:  (*posture.MinVersionCheck)(osVersionCheck.Darwin),
			Ios:     (*posture.MinVersionCheck)(osVersionCheck.Ios),
			Linux:   (*posture.MinKernelVersionCheck)(osVersionCheck.Linux),
			Windows: (*posture.MinKernelVersionCheck)(osVersionCheck.Windows),
		})
	}

	if geoLocationCheck := req.Checks.GeoLocationCheck; geoLocationCheck != nil {
		postureChecks.Checks = append(postureChecks.Checks, toPostureGeoLocationCheck(geoLocationCheck))
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
		req.Checks.GeoLocationCheck == nil) {
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

		for _, loc := range geoLocationCheck.Locations {
			if loc.CountryCode == "" {
				return status.Errorf(status.InvalidArgument, "country code for geolocation check shouldn't be empty")
			}

			if loc.CityName == nil && loc.CityGeonameId == nil {
				return status.Errorf(status.InvalidArgument, "city name or city geoname id for geolocation check shouldn't be empty")
			}
		}

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
				MinVersion: versionCheck.MinVersion,
			}
		case posture.OSVersionCheckName:
			osCheck := check.(*posture.OSVersionCheck)
			checks.OsVersionCheck = &api.OSVersionCheck{
				Android: (*api.MinVersionCheck)(osCheck.Android),
				Darwin:  (*api.MinVersionCheck)(osCheck.Darwin),
				Ios:     (*api.MinVersionCheck)(osCheck.Ios),
				Linux:   (*api.MinKernelVersionCheck)(osCheck.Linux),
				Windows: (*api.MinKernelVersionCheck)(osCheck.Windows),
			}
		case posture.GeoLocationCheckName:
			geoLocationCheck := check.(*posture.GeoLocationCheck)
			checks.GeoLocationCheck = toGeoLocationCheckResponse(geoLocationCheck)
		}
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
		locations = append(locations, api.Location{
			CityGeonameId: &loc.CityGeoNameID,
			CityName:      &loc.CityName,
			CountryCode:   loc.CountryCode,
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
		var (
			cityName      string
			cityGeoNameID int
		)

		if loc.CityName != nil {
			cityName = *loc.CityName
		}
		if loc.CityGeonameId != nil {
			cityGeoNameID = *loc.CityGeonameId
		}

		locations = append(locations, posture.Location{
			CountryCode:   loc.CountryCode,
			CityName:      cityName,
			CityGeoNameID: cityGeoNameID,
		})
	}

	return &posture.GeoLocationCheck{
		Action:    string(apiGeoLocationCheck.Action),
		Locations: locations,
	}
}
