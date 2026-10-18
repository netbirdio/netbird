package version

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	goversion "github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"
)

const (
	fetchPeriod = 30 * time.Minute
)

var (
	versionURL = "https://pkgs.netbird.io/releases/latest/version"
)

// Update fetch the version info periodically and notify the onUpdateListener in case the UI version or the
// daemon version are deprecated
type Update struct {
	httpAgent       string
	uiVersion       *goversion.Version
	daemonVersion   *goversion.Version
	latestAvailable *goversion.Version
	versionsLock    sync.Mutex

	// fetcherLock guards the fetcher lifecycle fields below.
	fetcherLock  sync.Mutex
	fetchStopped bool
	fetchCancel  context.CancelFunc
	fetcherDone  chan struct{}

	onUpdateListener func()
	listenerLock     sync.Mutex
}

// NewUpdate instantiate Update and start to fetch the new version information
func NewUpdate(httpAgent string) *Update {
	currentVersion, err := goversion.NewVersion(version)
	if err != nil {
		currentVersion, _ = goversion.NewVersion("0.0.0")
	}

	u := &Update{
		httpAgent: httpAgent,
		uiVersion: currentVersion,
	}

	return u
}

func NewUpdateAndStart(httpAgent string) *Update {
	u := NewUpdate(httpAgent)
	go u.StartFetcher()

	return u
}

// StopWatch stops the version info fetch loop, cancelling an in-flight request, and waits
// for StartFetcher to return. It is safe to call more than once, and a StartFetcher that
// runs after it returns immediately.
func (u *Update) StopWatch() {
	u.fetcherLock.Lock()
	u.fetchStopped = true
	cancel, done := u.fetchCancel, u.fetcherDone
	u.fetcherLock.Unlock()

	if cancel == nil {
		return
	}
	cancel()
	<-done
}

// SetDaemonVersion update the currently running daemon version. If new version is available it will trigger
// the onUpdateListener
func (u *Update) SetDaemonVersion(newVersion string) bool {
	daemonVersion, err := goversion.NewVersion(newVersion)
	if err != nil {
		daemonVersion, _ = goversion.NewVersion("0.0.0")
	}

	u.versionsLock.Lock()
	if u.daemonVersion != nil && u.daemonVersion.Equal(daemonVersion) {
		u.versionsLock.Unlock()
		return false
	}

	u.daemonVersion = daemonVersion
	u.versionsLock.Unlock()
	return u.checkUpdate()
}

// SetOnUpdateListener set new update listener
func (u *Update) SetOnUpdateListener(updateFn func()) {
	u.listenerLock.Lock()
	defer u.listenerLock.Unlock()

	u.onUpdateListener = updateFn
	if u.isUpdateAvailable() {
		u.onUpdateListener()
	}
}

func (u *Update) LatestVersion() *goversion.Version {
	u.versionsLock.Lock()
	defer u.versionsLock.Unlock()
	return u.latestAvailable
}

// StartFetcher fetches the version info now and then every fetchPeriod until StopWatch is
// called. It blocks, so callers run it in a goroutine. Only the first call starts a loop;
// later calls, and any call after StopWatch, return immediately.
func (u *Update) StartFetcher() {
	u.fetcherLock.Lock()
	if u.fetchStopped || u.fetcherDone != nil {
		u.fetcherLock.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	u.fetchCancel, u.fetcherDone = cancel, done
	u.fetcherLock.Unlock()

	defer close(done)
	u.fetchLoop(ctx)
}

func (u *Update) fetchLoop(ctx context.Context) {
	ticker := time.NewTicker(fetchPeriod)
	defer ticker.Stop()

	for {
		if changed := u.fetchVersion(ctx); changed {
			u.checkUpdate()
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (u *Update) fetchVersion(ctx context.Context) bool {
	log.Debugf("fetching version info from %s", versionURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, versionURL, nil)
	if err != nil {
		log.Errorf("failed to create request for version info: %s", err)
		return false
	}

	req.Header.Set("User-Agent", u.httpAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			log.Debugf("version info fetch cancelled: %s", err)
			return false
		}
		log.Errorf("failed to fetch version info: %s", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Errorf("invalid status code: %d", resp.StatusCode)
		return false
	}

	if resp.ContentLength > 100 {
		log.Errorf("too large response: %d", resp.ContentLength)
		return false
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("failed to read content: %s", err)
		return false
	}

	latestAvailable, err := goversion.NewVersion(string(content))
	if err != nil {
		log.Errorf("failed to parse the version string: %s", err)
		return false
	}

	u.versionsLock.Lock()
	defer u.versionsLock.Unlock()

	if u.latestAvailable.Equal(latestAvailable) {
		return false
	}
	u.latestAvailable = latestAvailable

	return true
}

func (u *Update) checkUpdate() bool {
	if !u.isUpdateAvailable() {
		return false
	}

	u.listenerLock.Lock()
	defer u.listenerLock.Unlock()
	if u.onUpdateListener == nil {
		return true
	}

	go u.onUpdateListener()
	return true
}

func (u *Update) isUpdateAvailable() bool {
	u.versionsLock.Lock()
	defer u.versionsLock.Unlock()

	if u.latestAvailable == nil {
		return false
	}

	if u.latestAvailable.GreaterThan(u.uiVersion) {
		return true
	}

	if u.daemonVersion == nil {
		return false
	}

	if u.latestAvailable.GreaterThan(u.daemonVersion) {
		return true
	}
	return false
}
