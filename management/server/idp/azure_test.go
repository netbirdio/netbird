package idp

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAzureJwtStillValid(t *testing.T) {
	type jwtStillValidTest struct {
		name           string
		inputTime      time.Time
		expectedResult bool
		message        string
	}

	jwtStillValidTestCase1 := jwtStillValidTest{
		name:           "JWT still valid",
		inputTime:      time.Now().Add(10 * time.Second),
		expectedResult: true,
		message:        "should be true",
	}
	jwtStillValidTestCase2 := jwtStillValidTest{
		name:           "JWT is invalid",
		inputTime:      time.Now(),
		expectedResult: false,
		message:        "should be false",
	}

	for _, testCase := range []jwtStillValidTest{jwtStillValidTestCase1, jwtStillValidTestCase2} {
		t.Run(testCase.name, func(t *testing.T) {
			config := AzureClientConfig{}

			creds := AzureCredentials{
				clientConfig: config,
			}
			creds.jwtToken.expiresInTime = testCase.inputTime

			assert.Equalf(t, testCase.expectedResult, creds.jwtStillValid(), testCase.message)
		})
	}
}

func TestAzureAuthenticate(t *testing.T) {
	type authenticateTest struct {
		name                    string
		inputCode               int
		inputResBody            string
		inputExpireToken        time.Time
		helper                  ManagerHelper
		expectedFuncExitErrDiff error
		expectedCode            int
		expectedToken           string
	}
	exp := 5
	token := newTestJWT(t, exp)

	authenticateTestCase1 := authenticateTest{
		name:                    "Get Cached token",
		inputExpireToken:        time.Now().Add(30 * time.Second),
		helper:                  JsonParser{},
		expectedFuncExitErrDiff: nil,
		expectedCode:            200,
		expectedToken:           "",
	}

	authenticateTestCase2 := authenticateTest{
		name:          "Get Good JWT Response",
		inputCode:     200,
		inputResBody:  fmt.Sprintf("{\"access_token\":\"%s\",\"scope\":\"read:users\",\"expires_in\":%d,\"token_type\":\"Bearer\"}", token, exp),
		helper:        JsonParser{},
		expectedCode:  200,
		expectedToken: token,
	}

	authenticateTestCase3 := authenticateTest{
		name:                    "Get Bad Status Code",
		inputCode:               400,
		inputResBody:            "{}",
		helper:                  JsonParser{},
		expectedFuncExitErrDiff: fmt.Errorf("unable to get azure token, statusCode 400"),
		expectedCode:            200,
		expectedToken:           "",
	}

	for _, testCase := range []authenticateTest{authenticateTestCase1, authenticateTestCase2, authenticateTestCase3} {
		t.Run(testCase.name, func(t *testing.T) {

			jwtReqClient := mockHTTPClient{
				resBody: testCase.inputResBody,
				code:    testCase.inputCode,
			}
			config := AzureClientConfig{}

			creds := AzureCredentials{
				clientConfig: config,
				httpClient:   &jwtReqClient,
				helper:       testCase.helper,
			}
			creds.jwtToken.expiresInTime = testCase.inputExpireToken

			_, err := creds.Authenticate()
			if err != nil {
				if testCase.expectedFuncExitErrDiff != nil {
					assert.EqualError(t, err, testCase.expectedFuncExitErrDiff.Error(), "errors should be the same")
				} else {
					t.Fatal(err)
				}
			}

			assert.Equalf(t, testCase.expectedToken, creds.jwtToken.AccessToken, "two tokens should be the same")
		})
	}
}

func TestAzureProfile(t *testing.T) {
	type azureProfileTest struct {
		name             string
		invite           bool
		inputProfile     azureProfile
		expectedUserData UserData
	}

	azureProfileTestCase1 := azureProfileTest{
		name:   "Good Request",
		invite: false,
		inputProfile: azureProfile{
			"id":                "test1",
			"displayName":       "John Doe",
			"userPrincipalName": "test1@test.com",
		},
		expectedUserData: UserData{
			Email: "test1@test.com",
			Name:  "John Doe",
			ID:    "test1",
		},
	}

	azureProfileTestCase2 := azureProfileTest{
		name:   "Missing User ID",
		invite: true,
		inputProfile: azureProfile{
			"displayName":       "John Doe",
			"userPrincipalName": "test2@test.com",
		},
		expectedUserData: UserData{
			Email: "test2@test.com",
			Name:  "John Doe",
		},
	}

	azureProfileTestCase3 := azureProfileTest{
		name:   "Missing User Name",
		invite: false,
		inputProfile: azureProfile{
			"id":                "test3",
			"userPrincipalName": "test3@test.com",
		},
		expectedUserData: UserData{
			ID:    "test3",
			Email: "test3@test.com",
		},
	}

	for _, testCase := range []azureProfileTest{azureProfileTestCase1, azureProfileTestCase2, azureProfileTestCase3} {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.expectedUserData.AppMetadata.WTPendingInvite = &testCase.invite
			userData := testCase.inputProfile.userData()

			assert.Equal(t, testCase.expectedUserData.ID, userData.ID, "User id should match")
			assert.Equal(t, testCase.expectedUserData.Email, userData.Email, "User email should match")
			assert.Equal(t, testCase.expectedUserData.Name, userData.Name, "User name should match")
		})
	}
}
