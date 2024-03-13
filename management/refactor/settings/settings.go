package settings

import "time"

type Settings interface {
	GetLicense() string
	GetPeerLoginExpiration() time.Duration
	SetPeerLoginExpiration(duration time.Duration)
	GetPeerLoginExpirationEnabled() bool
	SetPeerLoginExpirationEnabled(bool)
}

type DefaultSettings struct {
}

func (s *DefaultSettings) GetLicense() string {
	return "selfhosted"
}

func (s *DefaultSettings) GetPeerLoginExpiration() time.Duration {
	return 0
}

func (s *DefaultSettings) SetPeerLoginExpiration(duration time.Duration) {

}

func (s *DefaultSettings) GetPeerLoginExpirationEnabled() bool {
	return false
}

func (s *DefaultSettings) SetPeerLoginExpirationEnabled(bool) {

}
