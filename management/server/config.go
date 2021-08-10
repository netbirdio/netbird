package server

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
	Stuns  []*Host
	Turns  []*Host
	Signal *Host

	Datadir string

	HttpConfig *HttpServerConfig
}

// HttpServerConfig is a config of the HTTP Management service server
type HttpServerConfig struct {
	LetsEncryptDomain string
	Address           string
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
	Password []byte
}
