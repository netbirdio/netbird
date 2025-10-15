package idp

import (
	"encoding/json"
	"math/rand"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
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
		random := rand.Intn(len(specialCharSet))
		password.WriteString(string(specialCharSet[random]))
	}

	//Set numeric
	for i := 0; i < minNum; i++ {
		random := rand.Intn(len(numberSet))
		password.WriteString(string(numberSet[random]))
	}

	//Set uppercase
	for i := 0; i < minUpperCase; i++ {
		random := rand.Intn(len(upperCharSet))
		password.WriteString(string(upperCharSet[random]))
	}

	remainingLength := passwordLength - minSpecialChar - minNum - minUpperCase
	for i := 0; i < remainingLength; i++ {
		random := rand.Intn(len(allCharSet))
		password.WriteString(string(allCharSet[random]))
	}
	inRune := []rune(password.String())
	rand.Shuffle(len(inRune), func(i, j int) {
		inRune[i], inRune[j] = inRune[j], inRune[i]
	})
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

// Provides the env variable name for use with idpTimeout function
const (
	idpTimeoutEnv = "NETBIRD_IDP_TIMEOUT"
	defaultTimeout = 10 * time.Second
)

// idpTimmeout returns a timeout value for the IDP
func idpTimeout() time.Duration {
	timeoutStr, ok := os.LookupEnv(idpTimeoutEnv)
	if !ok || timeoutStr == "" {
		return defaultTimeout
	}

	timeoutInt, err := strconv.Atoi(timeoutStr)
	if err != nil {
		log.Printf("Invalid value for %s: %q. Error: %v, using default %s", idpTimeoutEnv, timeoutStr, err, defaultTimeout)
		return defaultTimeout
	}

	return time.Duration(timeoutInt) * time.Second
}
