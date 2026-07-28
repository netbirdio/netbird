package grpc

import (
	"errors"
	"fmt"
)

type SyncMessageVersion uint16

const (
	Base SyncMessageVersion = iota
	ComponentNetworkMap
)

const DefaultSyncMessageVersion = Base
const HighestSyncMessageVersion = ComponentNetworkMap

var ErrorUnrecognizedSyncMessageVersion = errors.New("unrecognized SyncMessageVersion")

func ValidateSyncMessageVersion(v *int) error {
	// empty list == we support all available versions
	if v == nil {
		return nil
	}
	if *v < 0 || *v > int(HighestSyncMessageVersion) {
		return fmt.Errorf("sync message version must between 0 and %d, %w", HighestSyncMessageVersion, ErrorUnrecognizedSyncMessageVersion)
	}
	return nil
}

// returns SyncMessage version from config, or highest available version if the config is missing or
// base if it is invalid
// the assumption is ValidateSyncMessageVersion() has been called before using SyncMessageVersionFromConfig()
func SyncMessageVersionFromConfig(v *int) SyncMessageVersion {
	if v == nil {
		return DefaultSyncMessageVersion
	}
	if *v < 0 || *v > int(HighestSyncMessageVersion) {
		return Base
	}

	return SyncMessageVersion(*v)
}

// convert per-account supported versions to SyncMessageVersion
// the assumption is ValidateSyncMessageVersion() has been called before using SyncMessageVersionsFromMap()
func SyncMessageVersionsFromMap(toconvert map[string]int) map[string]SyncMessageVersion {
	// no per-account overrides
	if len(toconvert) == 0 {
		return nil
	}

	toret := make(map[string]SyncMessageVersion)

	for account, version := range toconvert {
		toret[account] = SyncMessageVersionFromConfig(&version)
	}
	return toret
}

// return highest common sync message version, or Default (which is always available)
func HighestCommonSyncMessageVersion(a SyncMessageVersion, b SyncMessageVersion) SyncMessageVersion {
	if a > b {
		return b
	}
	return a
}
