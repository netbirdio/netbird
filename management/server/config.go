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
	AuthDomain        string
	AuthClientId      string
	AuthClientSecret  string
	AuthCallback      string
	Session           *Session
}

// Session is a configuration for user HTTP session
type Session struct {
	// CookieCodecs is a key pair of a auth key and a encryption key to be used for securing cookies
	CookieCodecs map[string]string
	// CookieDomain is a user session cookie domain to be set
	CookieDomain string
	// MaxAgeSec is a user session duration in seconds
	MaxAgeSec int
}

// Host represents a Wiretrustee host (e.g. STUN, TURN, Signal)
type Host struct {
	Proto Protocol
	// URI e.g. turns://stun.wiretrustee.com:4430 or signal.wiretrustee.com:10000
	URI      string
	Username string
	Password []byte
}
