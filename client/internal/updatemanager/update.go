package updatemanager

import v "github.com/hashicorp/go-version"

type UpdateInterface interface {
	StopWatch()
	SetDaemonVersion(newVersion string) bool
	SetOnUpdateListener(updateFn func())
	LatestVersion() *v.Version
	StartFetcher()
}
