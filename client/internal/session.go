package internal

import (
	"context"
	"net/url"
	"time"
)

type SessionWatcher struct {
	ctx        context.Context
	privateKey string
	mgmURL     *url.URL
	sshKey     string

	watchTicker *time.Ticker

	onExpireListener func()
}

// NewSessionWatcher creates a new instance of SessionWatcher.
func NewSessionWatcher(ctx context.Context, configPath string) (*SessionWatcher, error) {
	cfg, err := ReadConfig(configPath)
	if err != nil {
		return nil, err
	}

	s := &SessionWatcher{
		ctx:         ctx,
		privateKey:  cfg.PrivateKey,
		mgmURL:      cfg.ManagementURL,
		sshKey:      cfg.SSHKey,
		watchTicker: time.NewTicker(10 * time.Second),
	}
	go s.startWatcher()
	return s, nil
}

// SetOnExpireListener sets the callback func to be called when the session expires.
func (s *SessionWatcher) SetOnExpireListener(onExpire func()) {
	s.onExpireListener = onExpire
}

// startWatcher starts the session watcher.
// It checks if login is required,
// if login is required and onExpireListener is set, it calls the onExpireListener.
func (s *SessionWatcher) startWatcher() {
	required, _ := IsLoginRequired(s.ctx, s.privateKey, s.mgmURL, s.sshKey)
	if required {
		if s.onExpireListener != nil {
			s.onExpireListener()
		}
	}

	for {
		select {
		case <-s.watchTicker.C:
			required, _ := IsLoginRequired(s.ctx, s.privateKey, s.mgmURL, s.sshKey)
			if required {
				if s.onExpireListener != nil {
					s.onExpireListener()
				}
			}
		}
	}
}

// StopWatch stops the watch ticker of the SessionWatcher,
// effectively stopping the session watching a process.
func (s *SessionWatcher) StopWatch() { s.watchTicker.Stop() }
