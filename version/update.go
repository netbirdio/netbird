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
	versionURL  = "https://pkgs.netbird.io/releases/latest/version"
	fetchPeriod = 30 * time.Minute
)

type Update struct {
	uiVersion     *goversion.Version
	daemonVersion *goversion.Version
	lastAvailable *goversion.Version
	versionsLock  sync.Mutex

	onUpdateListener func(version string)
	listenerLock     sync.Mutex
}

func NewUpdate() *Update {
	currentVersion, err := goversion.NewVersion(version)
	if err != nil {
		currentVersion, _ = goversion.NewVersion("0.0.0")
	}

	lastAvailable, _ := goversion.NewVersion("0.0.0")

	u := &Update{
		lastAvailable: lastAvailable,
		uiVersion:     currentVersion,
	}

	go u.startFetcher()
	return u
}

func (u *Update) SetDaemonVersion(newVersion string) {
	daemonVersion, err := goversion.NewVersion(newVersion)
	if err != nil {
		daemonVersion, _ = goversion.NewVersion("0.0.0")
	}

	u.versionsLock.Lock()
	if u.daemonVersion != nil && u.daemonVersion.Equal(daemonVersion) {
		u.versionsLock.Unlock()
		return
	}

	u.daemonVersion = daemonVersion
	u.versionsLock.Unlock()
	u.checkUpdate()
}

func (u *Update) SetOnUpdateListener(updateFn func(version string)) {
	u.listenerLock.Lock()
	defer u.listenerLock.Unlock()

	u.onUpdateListener = updateFn
	if u.isUpdateAvailable() {
		u.onUpdateListener(version)
	}
}

func (u *Update) startFetcher() {
	changed := u.fetchVersion()
	if changed {
		u.checkUpdate()
	}

	uptimeTicker := time.NewTicker(fetchPeriod)
	for range uptimeTicker.C {
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

	lastAvailable, err := goversion.NewVersion(string(content))
	if err != nil {
		log.Errorf("faield to parse the version string: %s", err)
		return false
	}

	u.versionsLock.Lock()
	defer u.versionsLock.Unlock()

	if u.lastAvailable.Equal(lastAvailable) {
		return false
	}
	u.lastAvailable = lastAvailable

	return true
}

func (u *Update) checkUpdate() {
	if !u.isUpdateAvailable() {
		return
	}

	u.listenerLock.Lock()
	defer u.listenerLock.Unlock()
	if u.onUpdateListener == nil {
		return
	}

	u.onUpdateListener(u.lastAvailable.String())
}

func (u *Update) isUpdateAvailable() bool {
	u.versionsLock.Lock()
	defer u.versionsLock.Unlock()

	if u.lastAvailable.GreaterThan(u.uiVersion) {
		return true
	}

	if u.daemonVersion == nil {
		return false
	}

	if u.lastAvailable.GreaterThan(u.daemonVersion) {
		return true
	}
	return false
}
