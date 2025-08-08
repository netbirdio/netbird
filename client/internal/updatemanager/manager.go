package updatemanager

import (
	"context"
	"fmt"
	"github.com/netbirdio/netbird/client/internal/peer"
	cProto "github.com/netbirdio/netbird/client/proto"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	v "github.com/hashicorp/go-version"
	"github.com/netbirdio/netbird/version"
)

const (
	latestVersion     = "latest"
	disableAutoUpdate = "disabled"
)

type UpdateManager struct {
	ctx            context.Context
	cancel         context.CancelFunc
	version        string
	update         *version.Update
	lastTrigger    time.Time
	statusRecorder *peer.Status
}

func NewUpdateManager(statusRecorder *peer.Status) *UpdateManager {
	update := version.NewUpdate("nb/client")
	ctx, cancel := context.WithCancel(context.Background())
	manager := &UpdateManager{
		update:         update,
		lastTrigger:    time.Now().Add(-10 * time.Minute),
		statusRecorder: statusRecorder,
		ctx:            ctx,
		cancel:         cancel,
		version:        disableAutoUpdate,
	}
	update.SetDaemonVersion(version.NetbirdVersion())
	update.SetOnUpdateListener(manager.CheckForUpdates)
	return manager
}

func (u *UpdateManager) SetVersion(v string) {
	if u.version != v {
		log.Tracef("Auto-update version set to %s", v)
		u.version = v
		go u.CheckForUpdates()
	}
}

func (u *UpdateManager) Stop() {
	u.update.StopWatch()
	u.cancel()
}

func (u *UpdateManager) CheckForUpdates() {
	if u.version == disableAutoUpdate {
		log.Trace("Skipped checking for updates, auto-update is disabled")
		return
	}
	currentVersionString := version.NetbirdVersion()
	updateVersionString := u.version
	if updateVersionString == latestVersion || updateVersionString == "" {
		if u.update.LatestAvailable == nil {
			log.Tracef("Latest version not fetched yet")
			return
		}
		updateVersionString = u.update.LatestAvailable.String()
	}
	currentVersion, err := v.NewVersion(currentVersionString)
	if err != nil {
		log.Errorf("Error checking for update, error parsing version `%s`: %v", currentVersionString, err)
		return
	}
	updateVersion, err := v.NewVersion(updateVersionString)
	if err != nil {
		log.Errorf("Error checking for update, error parsing version `%s`: %v", updateVersionString, err)
		return
	}
	if currentVersion.LessThan(updateVersion) {
		if u.lastTrigger.Add(5 * time.Minute).Before(time.Now()) {
			u.lastTrigger = time.Now()
			log.Debugf("Auto-update triggered, current version: %s, target version: %s", currentVersionString, updateVersionString)
			u.statusRecorder.PublishEvent(
				cProto.SystemEvent_INFO,
				cProto.SystemEvent_SYSTEM,
				"Automatically updating client",
				"Your client version is older than auto-update version set in Management, updating client now.",
				nil,
			)
			err = u.triggerUpdate(updateVersionString)
			if err != nil {
				log.Errorf("Error triggering auto-update: %v", err)
			}
		}
	} else {
		log.Trace("Current version is equal to or higher than auto-update version")
	}
}

func downloadFileToTemporaryDir(ctx context.Context, fileURL string) (string, error) { //nolint:unused
	tempDir, err := os.MkdirTemp("", "netbird-installer-*")
	if err != nil {
		return "", fmt.Errorf("error creating temporary directory: %w", err)
	}
	fileNameParts := strings.Split(fileURL, "/")
	out, err := os.Create(filepath.Join(tempDir, fileNameParts[len(fileNameParts)-1]))
	if err != nil {
		return "", fmt.Errorf("error creating temporary file: %w", err)
	}
	defer func() {
		if err := out.Close(); err != nil {
			log.Errorf("Error closing temporary file: %v", err)
		}
	}()

	req, err := http.NewRequestWithContext(ctx, "GET", fileURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating file download request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error downloading file: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Errorf("Error closing response body: %v", err)
		}
	}()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return "", fmt.Errorf("error downloading file: %w", err)
	}

	log.Tracef("Downloaded update file to %s", out.Name())

	return out.Name(), nil
}

func urlWithVersionArch(url, version string) string { //nolint:unused
	url = strings.ReplaceAll(url, "%version", version)
	url = strings.ReplaceAll(url, "%arch", runtime.GOARCH)
	return url
}
