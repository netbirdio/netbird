package idp

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/netbirdio/netbird/management/server/telemetry"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
)

// Auth0Manager auth0 manager client instance
type Auth0Manager struct {
	authIssuer  string
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
}

// Auth0ClientConfig auth0 manager client configurations
type Auth0ClientConfig struct {
	Audience     string
	AuthIssuer   string
	ClientID     string
	ClientSecret string
	GrantType    string
}

// auth0JWTRequest payload struct to request a JWT Token
type auth0JWTRequest struct {
	Audience     string `json:"audience"`
	AuthIssuer   string `json:"auth_issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	GrantType    string `json:"grant_type"`
}

// Auth0Credentials auth0 authentication information
type Auth0Credentials struct {
	clientConfig Auth0ClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	jwtToken     JWTToken
	mux          sync.Mutex
	appMetrics   telemetry.AppMetrics
}

// createUserRequest is a user create request
type createUserRequest struct {
	Email       string      `json:"email"`
	Name        string      `json:"name"`
	AppMeta     AppMetadata `json:"app_metadata"`
	Connection  string      `json:"connection"`
	Password    string      `json:"password"`
	VerifyEmail bool        `json:"verify_email"`
}

// userExportJobRequest is a user export request struct
type userExportJobRequest struct {
	Format string              `json:"format"`
	Fields []map[string]string `json:"fields"`
}

// userExportJobResponse is a user export response struct
type userExportJobResponse struct {
	Type         string    `json:"type"`
	Status       string    `json:"status"`
	ConnectionID string    `json:"connection_id"`
	Format       string    `json:"format"`
	Limit        int       `json:"limit"`
	Connection   string    `json:"connection"`
	CreatedAt    time.Time `json:"created_at"`
	ID           string    `json:"id"`
}

// userExportJobStatusResponse is a user export status response struct
type userExportJobStatusResponse struct {
	Type         string    `json:"type"`
	Status       string    `json:"status"`
	ConnectionID string    `json:"connection_id"`
	Format       string    `json:"format"`
	Limit        int       `json:"limit"`
	Location     string    `json:"location"`
	Connection   string    `json:"connection"`
	CreatedAt    time.Time `json:"created_at"`
	ID           string    `json:"id"`
}

// userVerificationJobRequest is a user verification request struct
type userVerificationJobRequest struct {
	UserID string `json:"user_id"`
}

// auth0Profile represents an Auth0 user profile response
type auth0Profile struct {
	AccountID     string `json:"wt_account_id"`
	PendingInvite bool   `json:"wt_pending_invite"`
	UserID        string `json:"user_id"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	CreatedAt     string `json:"created_at"`
	LastLogin     string `json:"last_login"`
}

// Connections represents a single Auth0 connection
// https://auth0.com/docs/api/management/v2/connections/get-connections
type Connection struct {
	Id                 string            `json:"id"`
	Name               string            `json:"name"`
	DisplayName        string            `json:"display_name"`
	IsDomainConnection bool              `json:"is_domain_connection"`
	Realms             []string          `json:"realms"`
	Metadata           map[string]string `json:"metadata"`
	Options            ConnectionOptions `json:"options"`
}

type ConnectionOptions struct {
	DomainAliases []string `json:"domain_aliases"`
}

// NewAuth0Manager creates a new instance of the Auth0Manager
func NewAuth0Manager(config Auth0ClientConfig, appMetrics telemetry.AppMetrics) (*Auth0Manager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}
	helper := JsonParser{}

	if config.AuthIssuer == "" {
		return nil, fmt.Errorf("auth0 IdP configuration is incomplete, AuthIssuer is missing")
	}

	if config.ClientID == "" {
		return nil, fmt.Errorf("auth0 IdP configuration is incomplete, ClientID is missing")
	}

	if config.ClientSecret == "" {
		return nil, fmt.Errorf("auth0 IdP configuration is incomplete, ClientSecret is missing")
	}

	if config.Audience == "" {
		return nil, fmt.Errorf("auth0 IdP configuration is incomplete, Audience is missing")
	}

	if config.GrantType == "" {
		return nil, fmt.Errorf("auth0 IdP configuration is incomplete, GrantType is missing")
	}

	credentials := &Auth0Credentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &Auth0Manager{
		authIssuer:  config.AuthIssuer,
		credentials: credentials,
		httpClient:  httpClient,
		helper:      helper,
		appMetrics:  appMetrics,
	}, nil
}

// jwtStillValid returns true if the token still valid and have enough time to be used and get a response from Auth0
func (c *Auth0Credentials) jwtStillValid() bool {
	return !c.jwtToken.expiresInTime.IsZero() && time.Now().Add(5*time.Second).Before(c.jwtToken.expiresInTime)
}

// requestJWTToken performs request to get jwt token
func (c *Auth0Credentials) requestJWTToken() (*http.Response, error) {
	var res *http.Response
	reqURL := c.clientConfig.AuthIssuer + "/oauth/token"

	p, err := c.helper.Marshal(auth0JWTRequest(c.clientConfig))
	if err != nil {
		return res, err
	}
	payload := strings.NewReader(string(p))

	req, err := http.NewRequest("POST", reqURL, payload)
	if err != nil {
		return res, err
	}

	req.Header.Add("content-type", "application/json")

	log.Debug("requesting new jwt token for idp manager")

	res, err = c.httpClient.Do(req)
	if err != nil {
		if c.appMetrics != nil {
			c.appMetrics.IDPMetrics().CountRequestError()
		}
		return res, err
	}

	if res.StatusCode != 200 {
		return res, fmt.Errorf("unable to get token, statusCode %d", res.StatusCode)
	}
	return res, nil
}

// parseRequestJWTResponse parses jwt raw response body and extracts token and expires in seconds
func (c *Auth0Credentials) parseRequestJWTResponse(rawBody io.ReadCloser) (JWTToken, error) {
	jwtToken := JWTToken{}
	body, err := io.ReadAll(rawBody)
	if err != nil {
		return jwtToken, err
	}

	err = c.helper.Unmarshal(body, &jwtToken)
	if err != nil {
		return jwtToken, err
	}
	if jwtToken.ExpiresIn == 0 && jwtToken.AccessToken == "" {
		return jwtToken, fmt.Errorf("error while reading response body, expires_in: %d and access_token: %s", jwtToken.ExpiresIn, jwtToken.AccessToken)
	}
	data, err := jwt.DecodeSegment(strings.Split(jwtToken.AccessToken, ".")[1])
	if err != nil {
		return jwtToken, err
	}
	// Exp maps into exp from jwt token
	var IssuedAt struct{ Exp int64 }
	err = json.Unmarshal(data, &IssuedAt)
	if err != nil {
		return jwtToken, err
	}
	jwtToken.expiresInTime = time.Unix(IssuedAt.Exp, 0)

	return jwtToken, nil
}

// Authenticate retrieves access token to use the Auth0 Management API
func (c *Auth0Credentials) Authenticate() (JWTToken, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c.appMetrics != nil {
		c.appMetrics.IDPMetrics().CountAuthenticate()
	}

	// If jwtToken has an expires time and we have enough time to do a request return immediately
	if c.jwtStillValid() {
		return c.jwtToken, nil
	}

	res, err := c.requestJWTToken()
	if err != nil {
		return c.jwtToken, err
	}
	defer func() {
		err = res.Body.Close()
		if err != nil {
			log.Errorf("error while closing get jwt token response body: %v", err)
		}
	}()

	jwtToken, err := c.parseRequestJWTResponse(res.Body)
	if err != nil {
		return c.jwtToken, err
	}

	c.jwtToken = jwtToken

	return c.jwtToken, nil
}

func batchRequestUsersURL(authIssuer, accountID string, page int, perPage int) (string, url.Values, error) {
	u, err := url.Parse(authIssuer + "/api/v2/users")
	if err != nil {
		return "", nil, err
	}
	q := u.Query()
	q.Set("page", strconv.Itoa(page))
	q.Set("search_engine", "v3")
	q.Set("per_page", strconv.Itoa(perPage))
	q.Set("q", "app_metadata.wt_account_id:"+accountID)
	u.RawQuery = q.Encode()

	return u.String(), q, nil
}

func requestByUserIDURL(authIssuer, userID string) string {
	return authIssuer + "/api/v2/users/" + userID
}

// GetAccount returns all the users for a given profile. Calls Auth0 API.
func (am *Auth0Manager) GetAccount(accountID string) ([]*UserData, error) {
	jwtToken, err := am.credentials.Authenticate()
	if err != nil {
		return nil, err
	}

	var list []*UserData

	// https://auth0.com/docs/manage-users/user-search/retrieve-users-with-get-users-endpoint#limitations
	// auth0 limitation of 1000 users via this endpoint
	resultsPerPage := 50
	for page := 0; page < 20; page++ {
		reqURL, query, err := batchRequestUsersURL(am.authIssuer, accountID, page, resultsPerPage)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequest(http.MethodGet, reqURL, strings.NewReader(query.Encode()))
		if err != nil {
			return nil, err
		}

		req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
		req.Header.Add("content-type", "application/json")

		res, err := am.httpClient.Do(req)
		if err != nil {
			if am.appMetrics != nil {
				am.appMetrics.IDPMetrics().CountRequestError()
			}
			return nil, err
		}

		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountGetAccount()
		}

		body, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}

		if res.StatusCode != 200 {
			return nil, fmt.Errorf("failed requesting user data from IdP %s", string(body))
		}

		var batch []UserData
		err = json.Unmarshal(body, &batch)
		if err != nil {
			return nil, err
		}

		log.Debugf("returned user batch for accountID %s on page %d, batch length %d", accountID, page, len(batch))

		err = res.Body.Close()
		if err != nil {
			return nil, err
		}

		for user := range batch {
			list = append(list, &batch[user])
		}

		if len(batch) == 0 || len(batch) < resultsPerPage {
			log.Debugf("finished loading users for accountID %s", accountID)
			return list, nil
		}
	}

	return list, nil
}

// GetUserDataByID requests user data from auth0 via ID
func (am *Auth0Manager) GetUserDataByID(userID string, appMetadata AppMetadata) (*UserData, error) {
	jwtToken, err := am.credentials.Authenticate()
	if err != nil {
		return nil, err
	}

	reqURL := requestByUserIDURL(am.authIssuer, userID)
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	res, err := am.httpClient.Do(req)
	if err != nil {
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, err
	}

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountGetUserDataByID()
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var userData UserData
	err = json.Unmarshal(body, &userData)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = res.Body.Close()
		if err != nil {
			log.Errorf("error while closing update user app metadata response body: %v", err)
		}
	}()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("unable to get UserData, statusCode %d", res.StatusCode)
	}

	return &userData, nil
}

// UpdateUserAppMetadata updates user app metadata based on userId and metadata map
func (am *Auth0Manager) UpdateUserAppMetadata(userID string, appMetadata AppMetadata) error {

	jwtToken, err := am.credentials.Authenticate()
	if err != nil {
		return err
	}

	reqURL := am.authIssuer + "/api/v2/users/" + userID

	data, err := am.helper.Marshal(map[string]any{"app_metadata": appMetadata})
	if err != nil {
		return err
	}

	payload := strings.NewReader(string(data))

	req, err := http.NewRequest("PATCH", reqURL, payload)
	if err != nil {
		return err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	log.Debugf("updating IdP metadata for user %s", userID)

	res, err := am.httpClient.Do(req)
	if err != nil {
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestError()
		}
		return err
	}

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountUpdateUserAppMetadata()
	}

	defer func() {
		err = res.Body.Close()
		if err != nil {
			log.Errorf("error while closing update user app metadata response body: %v", err)
		}
	}()

	if res.StatusCode != 200 {
		return fmt.Errorf("unable to update the appMetadata, statusCode %d", res.StatusCode)
	}

	return nil
}

func buildCreateUserRequestPayload(email, name, accountID, invitedByEmail string) (string, error) {
	invite := true
	req := &createUserRequest{
		Email: email,
		Name:  name,
		AppMeta: AppMetadata{
			WTAccountID:     accountID,
			WTPendingInvite: &invite,
			WTInvitedBy:     invitedByEmail,
		},
		Connection:  "Username-Password-Authentication",
		Password:    GeneratePassword(8, 1, 1, 1),
		VerifyEmail: true,
	}

	str, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	return string(str), nil
}

func buildUserExportRequest() (string, error) {
	req := &userExportJobRequest{}
	fields := make([]map[string]string, 0)

	for _, field := range []string{"created_at", "last_login", "user_id", "email", "name"} {
		fields = append(fields, map[string]string{"name": field})
	}

	fields = append(fields, map[string]string{
		"name":      "app_metadata.wt_account_id",
		"export_as": "wt_account_id",
	})

	fields = append(fields, map[string]string{
		"name":      "app_metadata.wt_pending_invite",
		"export_as": "wt_pending_invite",
	})

	req.Format = "json"
	req.Fields = fields

	str, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	return string(str), nil
}

func (am *Auth0Manager) createRequest(
	method string, endpoint string, body io.Reader,
) (*http.Request, error) {
	jwtToken, err := am.credentials.Authenticate()
	if err != nil {
		return nil, err
	}

	reqURL := am.authIssuer + endpoint

	req, err := http.NewRequest(method, reqURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)

	return req, nil
}

func (am *Auth0Manager) createPostRequest(endpoint string, payloadStr string) (*http.Request, error) {
	req, err := am.createRequest("POST", endpoint, strings.NewReader(payloadStr))
	if err != nil {
		return nil, err
	}
	req.Header.Add("content-type", "application/json")

	return req, nil
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (am *Auth0Manager) GetAllAccounts() (map[string][]*UserData, error) {
	payloadString, err := buildUserExportRequest()
	if err != nil {
		return nil, err
	}

	exportJobReq, err := am.createPostRequest("/api/v2/jobs/users-exports", payloadString)
	if err != nil {
		return nil, err
	}

	jobResp, err := am.httpClient.Do(exportJobReq)
	if err != nil {
		log.Debugf("Couldn't get job response %v", err)
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, err
	}

	defer func() {
		err = jobResp.Body.Close()
		if err != nil {
			log.Errorf("error while closing update user app metadata response body: %v", err)
		}
	}()
	if jobResp.StatusCode != 200 {
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to update the appMetadata, statusCode %d", jobResp.StatusCode)
	}

	var exportJobResp userExportJobResponse

	body, err := io.ReadAll(jobResp.Body)
	if err != nil {
		log.Debugf("Couldn't read export job response; %v", err)
		return nil, err
	}

	err = am.helper.Unmarshal(body, &exportJobResp)
	if err != nil {
		log.Debugf("Couldn't unmarshal export job response; %v", err)
		return nil, err
	}

	if exportJobResp.ID == "" {
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("couldn't get an batch id status %d, %s, response body: %v", jobResp.StatusCode, jobResp.Status, exportJobResp)
	}

	log.Debugf("batch id status %d, %s, response body: %v", jobResp.StatusCode, jobResp.Status, exportJobResp)

	done, downloadLink, err := am.checkExportJobStatus(exportJobResp.ID)
	if err != nil {
		log.Debugf("Failed at getting status checks from exportJob; %v", err)
		return nil, err
	}

	if done {
		return am.downloadProfileExport(downloadLink)
	}

	return nil, fmt.Errorf("failed extracting user profiles from auth0")
}

// GetUserByEmail searches users with a given email. If no users have been found, this function returns an empty list.
// This function can return multiple users. This is due to the Auth0 internals - there could be multiple users with
// the same email but different connections that are considered as separate accounts (e.g., Google and username/password).
func (am *Auth0Manager) GetUserByEmail(email string) ([]*UserData, error) {
	jwtToken, err := am.credentials.Authenticate()
	if err != nil {
		return nil, err
	}
	reqURL := am.authIssuer + "/api/v2/users-by-email?email=" + url.QueryEscape(email)
	body, err := doGetReq(am.httpClient, reqURL, jwtToken.AccessToken)
	if err != nil {
		return nil, err
	}

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountGetUserByEmail()
	}

	userResp := []*UserData{}

	err = am.helper.Unmarshal(body, &userResp)
	if err != nil {
		log.Debugf("Couldn't unmarshal export job response; %v", err)
		return nil, err
	}

	return userResp, nil
}

// CreateUser creates a new user in Auth0 Idp and sends an invite
func (am *Auth0Manager) CreateUser(email, name, accountID, invitedByEmail string) (*UserData, error) {

	payloadString, err := buildCreateUserRequestPayload(email, name, accountID, invitedByEmail)
	if err != nil {
		return nil, err
	}
	req, err := am.createPostRequest("/api/v2/users", payloadString)
	if err != nil {
		return nil, err
	}

	if am.appMetrics != nil {
		am.appMetrics.IDPMetrics().CountCreateUser()
	}

	resp, err := am.httpClient.Do(req)
	if err != nil {
		log.Debugf("Couldn't get job response %v", err)
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestError()
		}
		return nil, err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			log.Errorf("error while closing create user response body: %v", err)
		}
	}()
	if !(resp.StatusCode == 200 || resp.StatusCode == 201) {
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return nil, fmt.Errorf("unable to create user, statusCode %d", resp.StatusCode)
	}

	var createResp UserData

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Debugf("Couldn't read export job response; %v", err)
		return nil, err
	}

	err = am.helper.Unmarshal(body, &createResp)
	if err != nil {
		log.Debugf("Couldn't unmarshal export job response; %v", err)
		return nil, err
	}

	if createResp.ID == "" {
		return nil, fmt.Errorf("couldn't create user: response %v", resp)
	}

	log.Debugf("created user %s in account %s", createResp.ID, accountID)

	return &createResp, nil
}

// InviteUserByID resend invitations to users who haven't activated,
// their accounts prior to the expiration period.
func (am *Auth0Manager) InviteUserByID(userID string) error {
	userVerificationReq := userVerificationJobRequest{
		UserID: userID,
	}

	payload, err := am.helper.Marshal(userVerificationReq)
	if err != nil {
		return err
	}

	req, err := am.createPostRequest("/api/v2/jobs/verification-email", string(payload))
	if err != nil {
		return err
	}

	resp, err := am.httpClient.Do(req)
	if err != nil {
		log.Debugf("Couldn't get job response %v", err)
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestError()
		}
		return err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			log.Errorf("error while closing invite user response body: %v", err)
		}
	}()
	if !(resp.StatusCode == 200 || resp.StatusCode == 201) {
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return fmt.Errorf("unable to invite user, statusCode %d", resp.StatusCode)
	}

	return nil
}

// DeleteUser from Auth0
func (am *Auth0Manager) DeleteUser(userID string) error {
	req, err := am.createRequest(http.MethodDelete, "/api/v2/users/"+url.QueryEscape(userID), nil)
	if err != nil {
		return err
	}

	resp, err := am.httpClient.Do(req)
	if err != nil {
		log.Debugf("execute delete request: %v", err)
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestError()
		}
		return err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			log.Errorf("close delete request body: %v", err)
		}
	}()
	if resp.StatusCode != 204 {
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return fmt.Errorf("unable to delete user, statusCode %d", resp.StatusCode)
	}

	return nil
}

// GetAllConnections returns detailed list of all connections filtered by given params.
// Note this method is not part of the IDP Manager interface as this is Auth0 specific.
func (am *Auth0Manager) GetAllConnections(strategy []string) ([]Connection, error) {
	var connections []Connection

	q := make(url.Values)
	q.Set("strategy", strings.Join(strategy, ","))

	req, err := am.createRequest(http.MethodGet, "/api/v2/connections?"+q.Encode(), nil)
	if err != nil {
		return connections, err
	}

	resp, err := am.httpClient.Do(req)
	if err != nil {
		log.Debugf("execute get connections request: %v", err)
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestError()
		}
		return connections, err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			log.Errorf("close get connections request body: %v", err)
		}
	}()
	if resp.StatusCode != 200 {
		if am.appMetrics != nil {
			am.appMetrics.IDPMetrics().CountRequestStatusError()
		}
		return connections, fmt.Errorf("unable to get connections, statusCode %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Debugf("Couldn't read get connections response; %v", err)
		return connections, err
	}

	err = am.helper.Unmarshal(body, &connections)
	if err != nil {
		log.Debugf("Couldn't unmarshal get connection response; %v", err)
		return connections, err
	}

	return connections, err
}

// checkExportJobStatus checks the status of the job created at CreateExportUsersJob.
// If the status is "completed", then return the downloadLink
func (am *Auth0Manager) checkExportJobStatus(jobID string) (bool, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	retry := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-ctx.Done():
			log.Debugf("Export job status stopped...\n")
			return false, "", ctx.Err()
		case <-retry.C:
			jwtToken, err := am.credentials.Authenticate()
			if err != nil {
				return false, "", err
			}

			statusURL := am.authIssuer + "/api/v2/jobs/" + jobID
			body, err := doGetReq(am.httpClient, statusURL, jwtToken.AccessToken)
			if err != nil {
				return false, "", err
			}

			var status userExportJobStatusResponse
			err = am.helper.Unmarshal(body, &status)
			if err != nil {
				return false, "", err
			}

			log.Debugf("current export job status is %v", status.Status)

			if status.Status != "completed" {
				continue
			}

			return true, status.Location, nil
		}
	}
}

// downloadProfileExport downloads user profiles from auth0 batch job
func (am *Auth0Manager) downloadProfileExport(location string) (map[string][]*UserData, error) {
	body, err := doGetReq(am.httpClient, location, "")
	if err != nil {
		return nil, err
	}

	bodyReader := bytes.NewReader(body)

	gzipReader, err := gzip.NewReader(bodyReader)
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(gzipReader)

	res := make(map[string][]*UserData)
	for decoder.More() {
		profile := auth0Profile{}
		err = decoder.Decode(&profile)
		if err != nil {
			return nil, err
		}
		if profile.AccountID != "" {
			if _, ok := res[profile.AccountID]; !ok {
				res[profile.AccountID] = []*UserData{}
			}
			res[profile.AccountID] = append(res[profile.AccountID],
				&UserData{
					ID:    profile.UserID,
					Name:  profile.Name,
					Email: profile.Email,
					AppMetadata: AppMetadata{
						WTAccountID:     profile.AccountID,
						WTPendingInvite: &profile.PendingInvite,
					},
				})
		}
	}

	return res, nil
}

// Boilerplate implementation for Get Requests.
func doGetReq(client ManagerHTTPClient, url, accessToken string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if accessToken != "" {
		req.Header.Add("authorization", "Bearer "+accessToken)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = res.Body.Close()
		if err != nil {
			log.Errorf("error while closing body for url %s: %v", url, err)
		}
	}()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("unable to get %s, statusCode %d", url, res.StatusCode)
	}
	return body, nil
}
