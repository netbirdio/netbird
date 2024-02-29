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

	fetchTicker *time.Ticker

	onExpireListener func()
}

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
		fetchTicker: time.NewTicker(10 * time.Second),
	}
	go s.startFetcher()
	return s, nil
}

func (s *SessionWatcher) SetOnExpireListener(onExpire func()) {
	s.onExpireListener = onExpire
}

func (s *SessionWatcher) startFetcher() {
	required, _ := IsLoginRequired(s.ctx, s.privateKey, s.mgmURL, s.sshKey)
	if required {
		if s.onExpireListener != nil {
			s.onExpireListener()
		}
	}

	for {
		select {
		case <-s.fetchTicker.C:
			required, _ := IsLoginRequired(s.ctx, s.privateKey, s.mgmURL, s.sshKey)
			if required {
				if s.onExpireListener != nil {
					s.onExpireListener()
				}
			}
		}
	}
}

func (s *SessionWatcher) StopWatch() { s.fetchTicker.Stop() }
