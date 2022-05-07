package server

import (
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/util"
	"net/url"
)

type Protocol string
type Provider string

const (
	UDP   Protocol = "udp"
	DTLS  Protocol = "dtls"
	TCP   Protocol = "tcp"
	HTTP  Protocol = "http"
	HTTPS Protocol = "https"
	AUTH0 Provider = "auth0"
)

// Config of the Management service
type Config struct {
	Stuns      []*Host
	TURNConfig *TURNConfig
	Signal     *Host

	Datadir string

	HttpConfig *HttpServerConfig

	IdpManagerConfig *idp.Config

	DeviceAuthorizationFlow *DeviceAuthorizationFlow
}

// TURNConfig is a config of the TURNCredentialsManager
type TURNConfig struct {
	TimeBasedCredentials bool
	CredentialsTTL       util.Duration
	Secret               string
	Turns                []*Host
}

// HttpServerConfig is a config of the HTTP Management service server
type HttpServerConfig struct {
	LetsEncryptDomain string
	//CertFile is the location of the certificate
	CertFile string
	//CertKey is the location of the certificate private key
	CertKey string
	Address string
	// AuthAudience identifies the recipients that the JWT is intended for (aud in JWT)
	AuthAudience string
	// AuthIssuer identifies principal that issued the JWT.
	AuthIssuer string
	// AuthKeysLocation is a location of JWT key set containing the public keys used to verify JWT
	AuthKeysLocation string
}

// Host represents a Wiretrustee host (e.g. STUN, TURN, Signal)
type Host struct {
	Proto Protocol
	// URI e.g. turns://stun.wiretrustee.com:4430 or signal.wiretrustee.com:10000
	URI      string
	Username string
	Password string
}

// DeviceAuthorizationFlow represents Device Authorization Flow information
// that can be used by the client to login initiate a Oauth 2.0 device authorization grant flow
// see https://datatracker.ietf.org/doc/html/rfc8628
type DeviceAuthorizationFlow struct {
	Provider       string
	ProviderConfig ProviderConfig
}

// ProviderConfig has all attributes needed to initiate a device authorization flow
type ProviderConfig struct {
	// ClientID An IDP application client id
	ClientID string
	// ClientSecret An IDP application client secret
	ClientSecret string
	// Domain An IDP API domain
	Domain string
	// Audience An Audience for to authorization validation
	Audience string
}

// validateURL validates input http url
func validateURL(httpURL string) bool {
	_, err := url.ParseRequestURI(httpURL)
	if err != nil {
		return false
	}
	return true
}
