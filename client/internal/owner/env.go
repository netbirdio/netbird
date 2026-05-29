package owner

import (
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// EnvOwnerUID is the environment variable that seeds the owner UID list for new config files.
// MDM deployments can set this (e.g. via --service-env NB_OWNER_UID=1000) so the first
// config created by the daemon pre-populates the owner without requiring "netbird up --owner".
// Multiple UIDs can be comma-separated: NB_OWNER_UID=1000,1001
const EnvOwnerUID = "NB_OWNER_UID"

// OwnerUIDsFromEnv parses NB_OWNER_UID into a UID slice.
// Returns nil if the variable is unset, allowing the caller to distinguish
// "not configured" from "explicitly empty".
func OwnerUIDsFromEnv() []UID {
	val := os.Getenv(EnvOwnerUID)
	if val == "" {
		return nil
	}

	parts := strings.Split(val, ",")
	uids := make([]UID, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		uid, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			log.Warnf("ignoring invalid UID %q in %s: %v", p, EnvOwnerUID, err)
			continue
		}
		uids = append(uids, UID(uid))
	}

	if len(uids) == 0 {
		log.Warnf("%s set but contains no valid UIDs, defaulting to root-only", EnvOwnerUID)
		return []UID{}
	}

	log.Infof("seeding owner UIDs from %s: %v", EnvOwnerUID, uids)
	return uids
}
