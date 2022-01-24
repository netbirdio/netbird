package server

import (
	"github.com/wiretrustee/wiretrustee/management/server/idp"
	"github.com/wiretrustee/wiretrustee/util"
)

type Protocol string

const (
	UDP   Protocol = "udp"
	DTLS  Protocol = "dtls"
	TCP   Protocol = "tcp"
	HTTP  Protocol = "http"
	HTTPS Protocol = "https"
)

// Config of the Management service
type Config struct {
	Stuns      []*Host
	TURNConfig *TURNConfig
	Signal     *Host

	Datadir string

	HttpConfig *HttpServerConfig

	IdpManagerConfig *idp.Config
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
