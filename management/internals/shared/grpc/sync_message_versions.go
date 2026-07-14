package grpc

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/netbirdio/netbird/shared/management/proto"
)

type SyncMessageVersion uint16

const (
	Base SyncMessageVersion = iota
	ComponentNetworkMap
)

var (
	AllSyncMessageVersions    = []SyncMessageVersion{Base, ComponentNetworkMap}
	ProtoToMessageSyncVersion = map[proto.PeerCapability]SyncMessageVersion{
		proto.PeerCapability_PeerCapabilityComponentNetworkMap: ComponentNetworkMap,
	}
	MessageSyncVersionToProto = map[SyncMessageVersion]proto.PeerCapability{
		ComponentNetworkMap: proto.PeerCapability_PeerCapabilityComponentNetworkMap,
	}
)

var ErrorUnrecognizedSyncMessageVersion = errors.New("unrecognized SyncMessageVersion")

func (sm SyncMessageVersion) String() string {
	return [...]string{"Base", "ComponentNetworkMap"}[sm]
}

func AllSupportedSyncMessageVersions() []SyncMessageVersion {
	return AllSyncMessageVersions
}

func ValidateSyncMessageVersions(tovalidate []string) error {
	// empty list == we support all available versions
	if len(tovalidate) == 0 {
		return nil
	}

	allversions := make(map[string]SyncMessageVersion, len(AllSyncMessageVersions))
	for _, v := range AllSyncMessageVersions {
		allversions[v.String()] = v
	}
	for _, s := range tovalidate {
		if _, ok := allversions[s]; !ok {
			return fmt.Errorf("%s: %w", s, ErrorUnrecognizedSyncMessageVersion)
		}
	}
	return nil
}

// convert human-readable versions to enums
// please note no validation on input strings is done, misses are silently discarded
// the assumption is ValidateSyncMessageVersions() has been called before using SyncMessageVersionsFromString()
func SyncMessageVersionsFromString(toconvert []string) []SyncMessageVersion {
	// empty list == we support all available versions
	if len(toconvert) == 0 {
		return AllSyncMessageVersions
	}

	allversions := make(map[string]SyncMessageVersion, len(AllSyncMessageVersions))
	for _, v := range AllSyncMessageVersions {
		allversions[v.String()] = v
	}
	toret := make([]SyncMessageVersion, 0)
	for _, s := range toconvert {
		toret = append(toret, allversions[s])
	}
	return toret
}

// convert per-account human-readable versions to enums
// please note no validation on versions strings is done, misses are silently discarded
// the assumption is ValidateSyncMessageVersions() has been called before using SyncMessageVersionsFromMap()
func SyncMessageVersionsFromMap(toconvert map[string][]string) map[string][]SyncMessageVersion {
	// no per-account overrides
	if len(toconvert) == 0 {
		return nil
	}

	allversions := make(map[string]SyncMessageVersion, len(AllSyncMessageVersions))
	for _, v := range AllSyncMessageVersions {
		allversions[v.String()] = v
	}

	toret := make(map[string][]SyncMessageVersion, len(toconvert))
	for account, versions := range toconvert {
		toret[account] = SyncMessageVersionsFromString(versions)
	}
	return toret
}

// these come from the client; peer capabilities are expected to contain all enabled sync message versions.
// an empty list is interpreted as all but the base version are disabled.
func SyncMessageVersionsFromProtoEnums(peerCapabilities []int32) []SyncMessageVersion {
	toret := make([]SyncMessageVersion, 0)
	for _, pc := range peerCapabilities {
		if _, ok := ProtoToMessageSyncVersion[proto.PeerCapability(pc)]; ok {
			toret = append(toret, ProtoToMessageSyncVersion[proto.PeerCapability(pc)])
		}
	}
	return toret
}

// return highest common sync message version, or Default (which is always available)
func CommonSyncMessageVersions(a []SyncMessageVersion, b []SyncMessageVersion) []SyncMessageVersion {
	toret := []SyncMessageVersion{Base}
	aversions := make(map[SyncMessageVersion]struct{})
	for _, va := range a {
		aversions[va] = struct{}{}
	}
	for _, vb := range b {
		if _, ok := aversions[vb]; ok && vb != Base { // we already added 'Base' version
			toret = append(toret, vb)
		}
	}
	slices.SortFunc(toret, func(a SyncMessageVersion, b SyncMessageVersion) int {
		return -1 * cmp.Compare(a, b)
	})

	return toret
}
