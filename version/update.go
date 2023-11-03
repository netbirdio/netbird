package version

import (
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
	uiVersion       *goversion.Version
	daemonVersion   *goversion.Version
	latestAvailable *goversion.Version
	versionsLock    sync.Mutex

	fetchTicker *time.Ticker
	fetchDone   chan struct{}

	onUpdateListener func()
	listenerLock     sync.Mutex
}

// NewUpdate instantiate Update and start to fetch the new version information
func NewUpdate() *Update {
	currentVersion, err := goversion.NewVersion(version)
	if err != nil {
		currentVersion, _ = goversion.NewVersion("0.0.0")
	}

	latestAvailable, _ := goversion.NewVersion("0.0.0")

	u := &Update{
		latestAvailable: latestAvailable,
		uiVersion:       currentVersion,
		fetchTicker:     time.NewTicker(fetchPeriod),
		fetchDone:       make(chan struct{}),
	}
	go u.startFetcher()
	return u
}

// StopWatch stop the version info fetch loop
func (u *Update) StopWatch() {
	u.fetchTicker.Stop()

	select {
	case u.fetchDone <- struct{}{}:
	default:
	}
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

func (u *Update) startFetcher() {
	changed := u.fetchVersion()
	if changed {
		u.checkUpdate()
	}

	select {
	case <-u.fetchDone:
		return
	case <-u.fetchTicker.C:
		changed := u.fetchVersion()
		if changed {
			u.checkUpdate()
		}
	}
}

func (u *Update) fetchVersion() bool {
	resp, err := http.Get(versionURL)
	if err != nil {
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
