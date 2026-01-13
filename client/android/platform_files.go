//go:build android

package android

// PlatformFiles groups paths to files used internally by the engine that can't be created/modified
// at their default locations due to android OS restrictions.
type PlatformFiles interface {
	ConfigurationFilePath() string
	StateFilePath() string
}
