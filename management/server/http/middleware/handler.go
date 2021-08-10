package middleware

import (
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt"
	"net/http"
)

//Jwks is a collection of JSONWebKeys obtained from Config.HttpServerConfig.AuthKeysLocation
type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

//JSONWebKeys is a representation of a Jason Web Key
type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

//NewJwtMiddleware creates new middleware to verify the JWT token sent via Authorization header
func NewJwtMiddleware(issuer string, audience string, keysLocation string) (*JWTMiddleware, error) {

	keys, err := getPemKeys(keysLocation)
	if err != nil {
		return nil, err
	}

	return New(Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			// Verify 'aud' claim
			checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(audience, false)
			if !checkAud {
				return token, errors.New("invalid audience")
			}
			// Verify 'issuer' claim
			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(issuer, false)
			if !checkIss {
				return token, errors.New("invalid issuer")
			}

			cert, err := getPemCert(token, keys)
			if err != nil {
				panic(err.Error())
			}

			result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
			return result, nil
		},
		SigningMethod: jwt.SigningMethodRS256,
	}), nil
}

func getPemKeys(keysLocation string) (*Jwks, error) {
	resp, err := http.Get(keysLocation)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jwks = &Jwks{}
	err = json.NewDecoder(resp.Body).Decode(jwks)

	if err != nil {
		return jwks, err
	}

	return jwks, err
}

func getPemCert(token *jwt.Token, jwks *Jwks) (string, error) {
	cert := ""

	for k, _ := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("unable to find appropriate key")
		return cert, err
	}

	return cert, nil
}
