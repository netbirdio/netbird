package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
)

func randomBytesInHex(count int) (string, error) {
	buf := make([]byte, count)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", fmt.Errorf("could not generate %d random bytes: %v", count, err)
	}

	return hex.EncodeToString(buf), nil
}

// isValidAccessToken is a simple validation of the access token
func isValidAccessToken(token string, audience string) error {
	if token == "" {
		return fmt.Errorf("token received is empty")
	}

	encodedClaims := strings.Split(token, ".")[1]
	claimsString, err := base64.RawURLEncoding.DecodeString(encodedClaims)
	if err != nil {
		return err
	}

	claims := Claims{}
	err = json.Unmarshal(claimsString, &claims)
	if err != nil {
		return err
	}

	if claims.Audience == nil {
		return fmt.Errorf("required token field audience is absent")
	}

	// Audience claim of JWT can be a string or an array of strings
	typ := reflect.TypeOf(claims.Audience)
	switch typ.Kind() {
	case reflect.String:
		if claims.Audience == audience {
			return nil
		}
	case reflect.Slice:
		for _, aud := range claims.Audience.([]interface{}) {
			if audience == aud {
				return nil
			}
		}
	}

	return fmt.Errorf("invalid JWT token audience field")
}

// isLinuxRunningDesktop checks if a Linux OS is running desktop environment.
func isLinuxRunningDesktop() bool {
	for _, env := range os.Environ() {
		log.Info("found the env: ", env)
		values := strings.Split(env, "=")
		if len(values) == 2 {
			key, value := values[0], values[1]
			if key == "XDG_CURRENT_DESKTOP" && value != "" {
				return true
			}
		}
	}
	return false
}
