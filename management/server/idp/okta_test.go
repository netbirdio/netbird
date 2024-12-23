package idp

import (
	"testing"

	"github.com/okta/okta-sdk-golang/v5/okta"
	"github.com/stretchr/testify/assert"
)

func TestParseOktaUser(t *testing.T) {
	type parseOktaUserTest struct {
		name             string
		inputUser        *okta.User
		expectedUserData *UserData
	}

	testCases := []parseOktaUserTest{
		{
			name: "valid okta user",
			inputUser: &okta.User{
				Id: okta.PtrString("123"),
				Profile: &okta.UserProfile{
					Email:     okta.PtrString("test@example.com"),
					FirstName: *okta.NewNullableString(okta.PtrString("John")),
					LastName:  *okta.NewNullableString(okta.PtrString("Doe")),
				},
			},
			expectedUserData: &UserData{
				Email: "test@example.com",
				Name:  "John Doe",
				ID:    "123",
			},
		},
		{
			name:             "invalid okta user",
			inputUser:        nil,
			expectedUserData: &UserData{},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			userData := parseOktaUser(tt.inputUser)
			assert.Equal(t, tt.expectedUserData, userData, "user data should match")
		})
	}
}
