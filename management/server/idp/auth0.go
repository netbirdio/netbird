package idp

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
)

// Auth0Manager auth0 manager client instance
type Auth0Manager struct {
	authIssuer  string
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	cachedUsers map[string]Auth0Profile
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
}

type Auth0Profile struct {
	UserID    string `json:"user_id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
	LastLogin string `json:"last_login"`
}

type UserExportJobResponse struct {
	Type         string    `json:"type"`
	Status       string    `json:"status"`
	ConnectionId string    `json:"connection_id"`
	Format       string    `json:"format"`
	Limit        int       `json:"limit"`
	Connection   string    `json:"connection"`
	CreatedAt    time.Time `json:"created_at"`
	Id           string    `json:"id"`
}

type ExportJobStatusResponse struct {
	Type         string    `json:"type"`
	Status       string    `json:"status"`
	ConnectionId string    `json:"connection_id"`
	Format       string    `json:"format"`
	Limit        int       `json:"limit"`
	Location     string    `json:"location"`
	Connection   string    `json:"connection"`
	CreatedAt    time.Time `json:"created_at"`
	Id           string    `json:"id"`
}

// NewAuth0Manager creates a new instance of the Auth0Manager
func NewAuth0Manager(config Auth0ClientConfig) (*Auth0Manager, error) {

	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}

	helper := JsonParser{}

	if config.ClientID == "" || config.ClientSecret == "" || config.GrantType == "" || config.Audience == "" || config.AuthIssuer == "" {
		return nil, fmt.Errorf("auth0 idp configuration is not complete")
	}

	if config.GrantType != "client_credentials" {
		return nil, fmt.Errorf("auth0 idp configuration failed. Grant Type should be client_credentials")
	}

	if !strings.HasPrefix(strings.ToLower(config.AuthIssuer), "https://") {
		return nil, fmt.Errorf("auth0 idp configuration failed. AuthIssuer should contain https://")
	}

	credentials := &Auth0Credentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
	}

	return &Auth0Manager{
		authIssuer:  config.AuthIssuer,
		credentials: credentials,
		httpClient:  httpClient,
		helper:      helper,
		cachedUsers: make(map[string]Auth0Profile),
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
	body, err := ioutil.ReadAll(rawBody)
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

func batchRequestUsersUrl(authIssuer, accountId string, page int) (string, url.Values, error) {
	u, err := url.Parse(authIssuer + "/api/v2/users")
	if err != nil {
		return "", nil, err
	}
	q := u.Query()
	q.Set("page", strconv.Itoa(page))
	q.Set("search_engine", "v3")
	q.Set("q", "app_metadata.wt_account_id:"+accountId)
	u.RawQuery = q.Encode()

	return u.String(), q, nil
}

func requestByUserIdUrl(authIssuer, userId string) string {
	return authIssuer + "/api/v2/users/" + userId
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
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("unable to get %s, statusCode %d", url, res.StatusCode)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// This creates an export job on auth0 for all users.
func (am *Auth0Manager) CreateExportUsersJob(accountId string) error {
	jwtToken, err := am.credentials.Authenticate()
	if err != nil {
		return err
	}

	reqURL := am.authIssuer + "/api/v2/jobs/users-exports"

	payloadString := fmt.Sprintf("{\"format\": \"json\"}")

	payload := strings.NewReader(payloadString)

	exportJobReq, err := http.NewRequest("POST", reqURL, payload)
	if err != nil {
		return err
	}
	exportJobReq.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	exportJobReq.Header.Add("content-type", "application/json")

	jobResp, err := am.httpClient.Do(exportJobReq)
	if err != nil {
		log.Debug("Couldn't get job response %v", err)
		return err
	}

	defer func() {
		err = jobResp.Body.Close()
		if err != nil {
			log.Errorf("error while closing update user app metadata response body: %v", err)
		}
	}()
	if jobResp.StatusCode != 200 {
		return fmt.Errorf("unable to update the appMetadata, statusCode %d", jobResp.StatusCode)
	}

	var exportJobResp UserExportJobResponse

	body, err := ioutil.ReadAll(jobResp.Body)
	if err != nil {
		log.Debug("Coudln't read export job response; %v", err)
		return err
	}

	err = am.helper.Unmarshal(body, &exportJobResp)
	if err != nil {
		log.Debug("Coudln't unmarshal export job response; %v", err)
		return err
	}

	if exportJobResp.Id == "" {
		return fmt.Errorf("couldn't get an batch id status %d, %s, response body: %v", jobResp.StatusCode, jobResp.Status, exportJobResp)
	}

	log.Debugf("batch id status %d, %s, response body: %v", jobResp.StatusCode, jobResp.Status, exportJobResp)

	ctx, cancel := context.WithTimeout(context.TODO(), 90*time.Second)
	defer cancel()

	done, downloadLink, err := am.checkExportJobStatus(ctx, exportJobResp.Id)
	if err != nil {
		log.Debugf("Failed at getting status checks from exportJob; %v", err)
		return err
	}

	if done {
		err = am.cacheUsers(downloadLink)
		if err != nil {
			log.Debugf("Failed to cache users via download link; %v", err)
		}
	}

	return nil
}

// Downloads the users from auth0 and caches it in memory
// We don't need
func (am *Auth0Manager) cacheUsers(location string) error {
	body, err := doGetReq(am.httpClient, location, "")
	if err != nil {
		log.Debugf("Can't download cached users; %v", err)
		return err
	}

	bodyReader := bytes.NewReader(body)

	gzipReader, err := gzip.NewReader(bodyReader)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(gzipReader)

	for decoder.More() {
		profile := Auth0Profile{}
		err = decoder.Decode(&profile)
		if err != nil {
			log.Errorf("Couldn't decode profile; %v", err)
			return err
		}
		am.cachedUsers[profile.UserID] = profile
	}

	return nil
}

// This checks the status of the job created at CreateExportUsersJob.
// If the status is "completed", then return the downloadLink
func (am *Auth0Manager) checkExportJobStatus(ctx context.Context, jobId string) (bool, string, error) {
	retry := time.NewTicker(500 * time.Millisecond)
	for {
		select {
		case <-ctx.Done():
			return false, "", ctx.Err()
		case <-retry.C:
			jwtToken, err := am.credentials.Authenticate()
			if err != nil {
				return false, "", err
			}

			statusUrl := am.authIssuer + "/api/v2/jobs/" + jobId
			body, err := doGetReq(am.httpClient, statusUrl, jwtToken.AccessToken)
			if err != nil {
				return false, "", err
			}

			var status ExportJobStatusResponse
			err = am.helper.Unmarshal(body, &status)
			if err != nil {
				return false, "", err
			}

			if status.Status != "completed" {
				continue
			}

			return true, status.Location, nil
		}
	}
}

func (am *Auth0Manager) GetBatchedUserData(accountId string) ([]*UserData, error) {
	// first time calling this
	// we need to check whether we need to call for users we don't have
	if len(am.cachedUsers) == 0 {
		err := am.CreateExportUsersJob(accountId)
		if err != nil {
			log.Debugf("Couldn't cache users; %v", err)
			return nil, err
		}
	}

	var list []*UserData

	for _, val := range am.cachedUsers {
		list = append(list, &UserData{
			Name:  val.Name,
			Email: val.Email,
			ID:    val.UserID,
		})
	}

	return list, nil
}

// GetBatchedUserData requests users in batches from Auth0
// func (am *Auth0Manager) GetBatchedUserData(accountId string) ([]*UserData, error) {
// 	jwtToken, err := am.credentials.Authenticate()
// 	if err != nil {
// 		return nil, err
// 	}

// 	var list []*UserData

// 	// https://auth0.com/docs/manage-users/user-search/retrieve-users-with-get-users-endpoint#limitations
// 	// auth0 limitation of 1000 users via this endpoint
// 	for page := 0; page < 20; page++ {
// 		reqURL, query, err := batchRequestUsersUrl(am.authIssuer, accountId, page)
// 		if err != nil {
// 			return nil, err
// 		}

// 		req, err := http.NewRequest(http.MethodGet, reqURL, strings.NewReader(query.Encode()))
// 		if err != nil {
// 			return nil, err
// 		}

// 		req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
// 		req.Header.Add("content-type", "application/json")

// 		res, err := am.httpClient.Do(req)
// 		if err != nil {
// 			return nil, err
// 		}

// 		body, err := io.ReadAll(res.Body)
// 		if err != nil {
// 			return nil, err
// 		}

// 		var batch []UserData
// 		err = json.Unmarshal(body, &batch)
// 		if err != nil {
// 			return nil, err
// 		}

// 		log.Debugf("requested batch; %v", batch)

// 		err = res.Body.Close()
// 		if err != nil {
// 			return nil, err
// 		}

// 		if res.StatusCode != 200 {
// 			return nil, fmt.Errorf("unable to request UserData from auth0, statusCode %d", res.StatusCode)
// 		}

// 		if len(batch) == 0 {
// 			return list, nil
// 		}

// 		for user := range batch {
// 			list = append(list, &batch[user])
// 		}
// 	}

// 	return list, nil
// }

// GetUserDataByID requests user data from auth0 via ID
func (am *Auth0Manager) GetUserDataByID(userId string, appMetadata AppMetadata) (*UserData, error) {
	jwtToken, err := am.credentials.Authenticate()
	if err != nil {
		return nil, err
	}

	reqURL := requestByUserIdUrl(am.authIssuer, userId)
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	res, err := am.httpClient.Do(req)
	if err != nil {
		return nil, err
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
func (am *Auth0Manager) UpdateUserAppMetadata(userId string, appMetadata AppMetadata) error {

	jwtToken, err := am.credentials.Authenticate()
	if err != nil {
		return err
	}

	reqURL := am.authIssuer + "/api/v2/users/" + userId

	data, err := am.helper.Marshal(appMetadata)
	if err != nil {
		return err
	}

	payloadString := fmt.Sprintf("{\"app_metadata\": %s}", string(data))

	payload := strings.NewReader(payloadString)

	req, err := http.NewRequest("PATCH", reqURL, payload)
	if err != nil {
		return err
	}
	req.Header.Add("authorization", "Bearer "+jwtToken.AccessToken)
	req.Header.Add("content-type", "application/json")

	log.Debugf("updating metadata for user %s", userId)

	res, err := am.httpClient.Do(req)
	if err != nil {
		return err
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
