package idp

import (
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseOktaUser(t *testing.T) {
	type parseOktaUserTest struct {
		name             string
		invite           bool
		inputProfile     *okta.User
		expectedUserData *UserData
		assertErrFunc    assert.ErrorAssertionFunc
	}

	parseOktaTestCase1 := parseOktaUserTest{
		name:   "Good Request",
		invite: true,
		inputProfile: &okta.User{
			Id: "123",
			Profile: &okta.UserProfile{
				"email":             "test@example.com",
				"firstName":         "John",
				"lastName":          "Doe",
				"wt_account_id":     "456",
				"wt_pending_invite": true,
			},
		},
		expectedUserData: &UserData{
			Email: "test@example.com",
			Name:  "John Doe",
			ID:    "123",
			AppMetadata: AppMetadata{
				WTAccountID: "456",
			},
		},
		assertErrFunc: assert.NoError,
	}

	parseOktaTestCase2 := parseOktaUserTest{
		name:             "Invalid okta user",
		invite:           true,
		inputProfile:     nil,
		expectedUserData: nil,
		assertErrFunc:    assert.Error,
	}

	parseOktaTestCase3 := parseOktaUserTest{
		name:   "Invalid pending invite type",
		invite: false,
		inputProfile: &okta.User{
			Id: "123",
			Profile: &okta.UserProfile{
				"email":             "test@example.com",
				"firstName":         "John",
				"lastName":          "Doe",
				"wt_account_id":     "456",
				"wt_pending_invite": "true",
			},
		},
		expectedUserData: nil,
		assertErrFunc:    assert.Error,
	}

	for _, testCase := range []parseOktaUserTest{parseOktaTestCase1, parseOktaTestCase2, parseOktaTestCase3} {
		t.Run(testCase.name, func(t *testing.T) {
			userData, err := parseOktaUser(testCase.inputProfile)
			testCase.assertErrFunc(t, err, testCase.assertErrFunc)

			if err == nil {
				testCase.expectedUserData.AppMetadata.WTPendingInvite = &testCase.invite
				assert.True(t, userDataEqual(testCase.expectedUserData, userData), "user data should match")
			}
		})

	}
}

// userDataEqual helper function to compare UserData structs for equality.
func userDataEqual(a, b *UserData) bool {
	if a.Email != b.Email || a.Name != b.Name || a.ID != b.ID {
		return false
	}
	if a.AppMetadata.WTAccountID != b.AppMetadata.WTAccountID {
		return false
	}

	if a.AppMetadata.WTPendingInvite != nil && b.AppMetadata.WTPendingInvite != nil &&
		*a.AppMetadata.WTPendingInvite != *b.AppMetadata.WTPendingInvite {
		return false
	}
	return true
}
