package idp

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/server/util"
)

var (
	lowerCharSet   = "abcdedfghijklmnopqrst"
	upperCharSet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	specialCharSet = "!@#$%&*"
	numberSet      = "0123456789"
	allCharSet     = lowerCharSet + upperCharSet + specialCharSet + numberSet
)

type JsonParser struct{}

func (JsonParser) Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func (JsonParser) Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// GeneratePassword generates user password
func GeneratePassword(passwordLength, minSpecialChar, minNum, minUpperCase int) string {
	var password strings.Builder

	//Set special character
	for i := 0; i < minSpecialChar; i++ {
		random := util.RandIntn(len(specialCharSet))
		password.WriteString(string(specialCharSet[random]))
	}

	//Set numeric
	for i := 0; i < minNum; i++ {
		random := util.RandIntn(len(numberSet))
		password.WriteString(string(numberSet[random]))
	}

	//Set uppercase
	for i := 0; i < minUpperCase; i++ {
		random := util.RandIntn(len(upperCharSet))
		password.WriteString(string(upperCharSet[random]))
	}

	remainingLength := passwordLength - minSpecialChar - minNum - minUpperCase
	for i := 0; i < remainingLength; i++ {
		random := util.RandIntn(len(allCharSet))
		password.WriteString(string(allCharSet[random]))
	}
	inRune := []rune(password.String())
	for i := len(inRune) - 1; i > 0; i-- {
		j := util.RandIntn(i + 1)
		inRune[i], inRune[j] = inRune[j], inRune[i]
	}
	return string(inRune)
}

// baseURL returns the base url  by concatenating
// the scheme and host components of the parsed URL.
func baseURL(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	return parsedURL.Scheme + "://" + parsedURL.Host
}

const (
	// Provides the env variable name for use with idpTimeout function
	idpTimeoutEnv = "NB_IDP_TIMEOUT"
	// Sets the defaultTimeout to 10s.
	defaultTimeout = 10 * time.Second
)

// idpTimeout returns a timeout value for the IDP
func idpTimeout() time.Duration {
	timeoutStr, ok := os.LookupEnv(idpTimeoutEnv)
	if !ok || timeoutStr == "" {
		return defaultTimeout
	}

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return defaultTimeout
	}
	return timeout
}
