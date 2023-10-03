package idp

import (
	"testing"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/stretchr/testify/assert"
)

func TestParseOktaUser(t *testing.T) {
	type parseOktaUserTest struct {
		name             string
		inputProfile     *okta.User
		expectedUserData *UserData
		assertErrFunc    assert.ErrorAssertionFunc
	}

	parseOktaTestCase1 := parseOktaUserTest{
		name: "Good Request",
		inputProfile: &okta.User{
			Id: "123",
			Profile: &okta.UserProfile{
				"email":     "test@example.com",
				"firstName": "John",
				"lastName":  "Doe",
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
		inputProfile:     nil,
		expectedUserData: nil,
		assertErrFunc:    assert.Error,
	}

	for _, testCase := range []parseOktaUserTest{parseOktaTestCase1, parseOktaTestCase2} {
		t.Run(testCase.name, func(t *testing.T) {
			userData, err := parseOktaUser(testCase.inputProfile)
			testCase.assertErrFunc(t, err, testCase.assertErrFunc)

			if err == nil {
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
	return true
}
