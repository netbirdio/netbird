package dex

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"

	"github.com/dexidp/dex/server"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/sql"

	"github.com/netbirdio/netbird/idp/dex/web"
)

// parseDuration parses a duration string (e.g., "6h", "24h", "168h").
func parseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

// YAMLConfig represents the YAML configuration file format (mirrors dex's config format)
type YAMLConfig struct {
	Issuer   string   `yaml:"issuer" json:"issuer"`
	Storage  Storage  `yaml:"storage" json:"storage"`
	Web      Web      `yaml:"web" json:"web"`
	GRPC     GRPC     `yaml:"grpc" json:"grpc"`
	OAuth2   OAuth2   `yaml:"oauth2" json:"oauth2"`
	Expiry   Expiry   `yaml:"expiry" json:"expiry"`
	Logger   Logger   `yaml:"logger" json:"logger"`
	Frontend Frontend `yaml:"frontend" json:"frontend"`

	// StaticConnectors are user defined connectors specified in the config file
	StaticConnectors []Connector `yaml:"connectors" json:"connectors"`

	// StaticClients cause the server to use this list of clients rather than
	// querying the storage. Write operations, like creating a client, will fail.
	StaticClients []storage.Client `yaml:"staticClients" json:"staticClients"`

	// If enabled, the server will maintain a list of passwords which can be used
	// to identify a user.
	EnablePasswordDB bool `yaml:"enablePasswordDB" json:"enablePasswordDB"`

	// StaticPasswords cause the server use this list of passwords rather than
	// querying the storage.
	StaticPasswords []Password `yaml:"staticPasswords" json:"staticPasswords"`
}

// Web is the config format for the HTTP server.
type Web struct {
	HTTP           string   `yaml:"http" json:"http"`
	HTTPS          string   `yaml:"https" json:"https"`
	AllowedOrigins []string `yaml:"allowedOrigins" json:"allowedOrigins"`
	AllowedHeaders []string `yaml:"allowedHeaders" json:"allowedHeaders"`
}

// GRPC is the config for the gRPC API.
type GRPC struct {
	Addr        string `yaml:"addr" json:"addr"`
	TLSCert     string `yaml:"tlsCert" json:"tlsCert"`
	TLSKey      string `yaml:"tlsKey" json:"tlsKey"`
	TLSClientCA string `yaml:"tlsClientCA" json:"tlsClientCA"`
}

// OAuth2 describes enabled OAuth2 extensions.
type OAuth2 struct {
	SkipApprovalScreen    bool     `yaml:"skipApprovalScreen" json:"skipApprovalScreen"`
	AlwaysShowLoginScreen bool     `yaml:"alwaysShowLoginScreen" json:"alwaysShowLoginScreen"`
	PasswordConnector     string   `yaml:"passwordConnector" json:"passwordConnector"`
	ResponseTypes         []string `yaml:"responseTypes" json:"responseTypes"`
	GrantTypes            []string `yaml:"grantTypes" json:"grantTypes"`
}

// Expiry holds configuration for the validity period of components.
type Expiry struct {
	SigningKeys    string              `yaml:"signingKeys" json:"signingKeys"`
	IDTokens       string              `yaml:"idTokens" json:"idTokens"`
	AuthRequests   string              `yaml:"authRequests" json:"authRequests"`
	DeviceRequests string              `yaml:"deviceRequests" json:"deviceRequests"`
	RefreshTokens  RefreshTokensExpiry `yaml:"refreshTokens" json:"refreshTokens"`
}

// RefreshTokensExpiry holds configuration for refresh token expiry.
type RefreshTokensExpiry struct {
	ReuseInterval     string `yaml:"reuseInterval" json:"reuseInterval"`
	ValidIfNotUsedFor string `yaml:"validIfNotUsedFor" json:"validIfNotUsedFor"`
	AbsoluteLifetime  string `yaml:"absoluteLifetime" json:"absoluteLifetime"`
	DisableRotation   bool   `yaml:"disableRotation" json:"disableRotation"`
}

// Logger holds configuration required to customize logging.
type Logger struct {
	Level  string `yaml:"level" json:"level"`
	Format string `yaml:"format" json:"format"`
}

// Frontend holds the server's frontend templates and assets config.
type Frontend struct {
	Dir     string            `yaml:"dir" json:"dir"`
	Theme   string            `yaml:"theme" json:"theme"`
	Issuer  string            `yaml:"issuer" json:"issuer"`
	LogoURL string            `yaml:"logoURL" json:"logoURL"`
	Extra   map[string]string `yaml:"extra" json:"extra"`
}

// Storage holds app's storage configuration.
type Storage struct {
	Type   string                 `yaml:"type" json:"type"`
	Config map[string]interface{} `yaml:"config" json:"config"`
}

// Password represents a static user configuration
type Password storage.Password

func (p *Password) UnmarshalYAML(node *yaml.Node) error {
	var data struct {
		Email       string `yaml:"email"`
		Username    string `yaml:"username"`
		UserID      string `yaml:"userID"`
		Hash        string `yaml:"hash"`
		HashFromEnv string `yaml:"hashFromEnv"`
	}
	if err := node.Decode(&data); err != nil {
		return err
	}
	*p = Password(storage.Password{
		Email:    data.Email,
		Username: data.Username,
		UserID:   data.UserID,
	})
	if len(data.Hash) == 0 && len(data.HashFromEnv) > 0 {
		data.Hash = os.Getenv(data.HashFromEnv)
	}
	if len(data.Hash) == 0 {
		return fmt.Errorf("no password hash provided for user %s", data.Email)
	}

	// If this value is a valid bcrypt, use it.
	_, bcryptErr := bcrypt.Cost([]byte(data.Hash))
	if bcryptErr == nil {
		p.Hash = []byte(data.Hash)
		return nil
	}

	// For backwards compatibility try to base64 decode this value.
	hashBytes, err := base64.StdEncoding.DecodeString(data.Hash)
	if err != nil {
		return fmt.Errorf("malformed bcrypt hash: %v", bcryptErr)
	}
	if _, err := bcrypt.Cost(hashBytes); err != nil {
		return fmt.Errorf("malformed bcrypt hash: %v", err)
	}
	p.Hash = hashBytes
	return nil
}

// Connector is a connector configuration that can unmarshal YAML dynamically.
type Connector struct {
	Type   string                 `yaml:"type" json:"type"`
	Name   string                 `yaml:"name" json:"name"`
	ID     string                 `yaml:"id" json:"id"`
	Config map[string]interface{} `yaml:"config" json:"config"`
}

// ToStorageConnector converts a Connector to storage.Connector type.
func (c *Connector) ToStorageConnector() (storage.Connector, error) {
	data, err := json.Marshal(c.Config)
	if err != nil {
		return storage.Connector{}, fmt.Errorf("failed to marshal connector config: %v", err)
	}

	return storage.Connector{
		ID:     c.ID,
		Type:   c.Type,
		Name:   c.Name,
		Config: data,
	}, nil
}

// StorageConfig is a configuration that can create a storage.
type StorageConfig interface {
	Open(logger *slog.Logger) (storage.Storage, error)
}

// OpenStorage opens a storage based on the config
func (s *Storage) OpenStorage(logger *slog.Logger) (storage.Storage, error) {
	switch s.Type {
	case "sqlite3":
		file, _ := s.Config["file"].(string)
		if file == "" {
			return nil, fmt.Errorf("sqlite3 storage requires 'file' config")
		}
		return (&sql.SQLite3{File: file}).Open(logger)
	case "postgres":
		dsn, _ := s.Config["dsn"].(string)
		if dsn == "" {
			return nil, fmt.Errorf("postgres storage requires 'dsn' config")
		}
		pg, err := parsePostgresDSN(dsn)
		if err != nil {
			return nil, fmt.Errorf("invalid postgres DSN: %w", err)
		}
		return pg.Open(logger)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", s.Type)
	}
}

// parsePostgresDSN parses a DSN into a sql.Postgres config.
// It accepts both URI format (postgres://user:pass@host:port/dbname?sslmode=disable)
// and libpq key=value format (host=localhost port=5432 dbname=mydb), including quoted values.
func parsePostgresDSN(dsn string) (*sql.Postgres, error) {
	var params map[string]string
	var err error

	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		params, err = parsePostgresURI(dsn)
	} else {
		params, err = parsePostgresKeyValue(dsn)
	}
	if err != nil {
		return nil, err
	}

	host := params["host"]
	if host == "" {
		host = "localhost"
	}

	var port uint16 = 5432
	if p, ok := params["port"]; ok && p != "" {
		v, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", p, err)
		}
		if v == 0 {
			return nil, fmt.Errorf("invalid port %q: must be non-zero", p)
		}
		port = uint16(v)
	}

	dbname := params["dbname"]
	if dbname == "" {
		return nil, fmt.Errorf("dbname is required in DSN")
	}

	pg := &sql.Postgres{
		NetworkDB: sql.NetworkDB{
			Host:     host,
			Port:     port,
			Database: dbname,
			User:     params["user"],
			Password: params["password"],
		},
	}

	if sslMode := params["sslmode"]; sslMode != "" {
		switch sslMode {
		case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
			pg.SSL.Mode = sslMode
		default:
			return nil, fmt.Errorf("unsupported sslmode %q: valid values are disable, allow, prefer, require, verify-ca, verify-full", sslMode)
		}
	}

	return pg, nil
}

// parsePostgresURI parses a postgres:// or postgresql:// URI into parameter key-value pairs.
func parsePostgresURI(dsn string) (map[string]string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid postgres URI: %w", err)
	}

	params := make(map[string]string)

	if u.User != nil {
		params["user"] = u.User.Username()
		if p, ok := u.User.Password(); ok {
			params["password"] = p
		}
	}
	if u.Hostname() != "" {
		params["host"] = u.Hostname()
	}
	if u.Port() != "" {
		params["port"] = u.Port()
	}

	dbname := strings.TrimPrefix(u.Path, "/")
	if dbname != "" {
		params["dbname"] = dbname
	}

	for k, v := range u.Query() {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}

	return params, nil
}

// parsePostgresKeyValue parses a libpq key=value DSN string, handling single-quoted values
// (e.g., password='my pass' host=localhost).
func parsePostgresKeyValue(dsn string) (map[string]string, error) {
	params := make(map[string]string)
	s := strings.TrimSpace(dsn)

	for s != "" {
		eqIdx := strings.IndexByte(s, '=')
		if eqIdx < 0 {
			break
		}
		key := strings.TrimSpace(s[:eqIdx])

		value, rest, err := parseDSNValue(s[eqIdx+1:])
		if err != nil {
			return nil, fmt.Errorf("%w for key %q", err, key)
		}

		params[key] = value
		s = strings.TrimSpace(rest)
	}

	return params, nil
}

// parseDSNValue parses the next value from a libpq key=value string positioned after the '='.
// It returns the parsed value and the remaining unparsed string.
func parseDSNValue(s string) (value, rest string, err error) {
	if len(s) > 0 && s[0] == '\'' {
		return parseQuotedDSNValue(s[1:])
	}
	// Unquoted value: read until whitespace.
	idx := strings.IndexAny(s, " \t\n")
	if idx < 0 {
		return s, "", nil
	}
	return s[:idx], s[idx:], nil
}

// parseQuotedDSNValue parses a single-quoted value starting after the opening quote.
// Libpq uses ” to represent a literal single quote inside quoted values.
func parseQuotedDSNValue(s string) (value, rest string, err error) {
	var buf strings.Builder
	for len(s) > 0 {
		if s[0] == '\'' {
			if len(s) > 1 && s[1] == '\'' {
				buf.WriteByte('\'')
				s = s[2:]
				continue
			}
			return buf.String(), s[1:], nil
		}
		buf.WriteByte(s[0])
		s = s[1:]
	}
	return "", "", fmt.Errorf("unterminated quoted value")
}

// Validate validates the configuration
func (c *YAMLConfig) Validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("no issuer specified in config file")
	}
	if c.Storage.Type == "" {
		return fmt.Errorf("no storage type specified in config file")
	}
	if c.Web.HTTP == "" && c.Web.HTTPS == "" {
		return fmt.Errorf("must supply a HTTP/HTTPS address to listen on")
	}
	if !c.EnablePasswordDB && len(c.StaticPasswords) != 0 {
		return fmt.Errorf("cannot specify static passwords without enabling password db")
	}
	return nil
}

// ToServerConfig converts YAMLConfig to dex server.Config
func (c *YAMLConfig) ToServerConfig(stor storage.Storage, logger *slog.Logger) server.Config {
	cfg := server.Config{
		Issuer:             c.Issuer,
		Storage:            stor,
		Logger:             logger,
		SkipApprovalScreen: c.OAuth2.SkipApprovalScreen,
		AllowedOrigins:     c.Web.AllowedOrigins,
		AllowedHeaders:     c.Web.AllowedHeaders,
		Web: server.WebConfig{
			Issuer:  c.Frontend.Issuer,
			LogoURL: c.Frontend.LogoURL,
			Theme:   c.Frontend.Theme,
			Dir:     c.Frontend.Dir,
			Extra:   c.Frontend.Extra,
		},
	}

	// Use embedded NetBird-styled templates if no custom dir specified
	if c.Frontend.Dir == "" {
		cfg.Web.WebFS = web.FS()
	}

	if len(c.OAuth2.ResponseTypes) > 0 {
		cfg.SupportedResponseTypes = c.OAuth2.ResponseTypes
	}

	// Apply expiry settings
	if c.Expiry.SigningKeys != "" {
		if d, err := parseDuration(c.Expiry.SigningKeys); err == nil {
			cfg.RotateKeysAfter = d
		}
	}
	if c.Expiry.IDTokens != "" {
		if d, err := parseDuration(c.Expiry.IDTokens); err == nil {
			cfg.IDTokensValidFor = d
		}
	}
	if c.Expiry.AuthRequests != "" {
		if d, err := parseDuration(c.Expiry.AuthRequests); err == nil {
			cfg.AuthRequestsValidFor = d
		}
	}
	if c.Expiry.DeviceRequests != "" {
		if d, err := parseDuration(c.Expiry.DeviceRequests); err == nil {
			cfg.DeviceRequestsValidFor = d
		}
	}

	return cfg
}

// GetRefreshTokenPolicy creates a RefreshTokenPolicy from the expiry config.
// This should be called after ToServerConfig and the policy set on the config.
func (c *YAMLConfig) GetRefreshTokenPolicy(logger *slog.Logger) (*server.RefreshTokenPolicy, error) {
	return server.NewRefreshTokenPolicy(
		logger,
		c.Expiry.RefreshTokens.DisableRotation,
		c.Expiry.RefreshTokens.ValidIfNotUsedFor,
		c.Expiry.RefreshTokens.AbsoluteLifetime,
		c.Expiry.RefreshTokens.ReuseInterval,
	)
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*YAMLConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg YAMLConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}
