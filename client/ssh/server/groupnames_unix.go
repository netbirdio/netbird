//go:build unix

package server

import (
	"errors"
	"fmt"
	"os/user"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/getent"
)

// resolveGroupNames resolves group IDs to names through the NSS-aware lookup, which also covers
// groups that a statically linked build cannot see in /etc/group. An ID without a group entry
// cannot match a group mapping and is skipped. Any other failure is returned, so that a
// mapping decision is never taken on a group list that may be incomplete.
func resolveGroupNames(ids []string) ([]string, error) {
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		g, err := getent.LookupGroupID(id)
		if err != nil {
			var unknown user.UnknownGroupIdError
			if errors.As(err, &unknown) {
				log.Debugf("group %s has no name, it cannot match a SELinux group mapping", id)
				continue
			}
			return nil, fmt.Errorf("resolve group %s: %w", id, err)
		}
		names = append(names, g.Name)
	}
	return names, nil
}

// groupNames resolves numeric group IDs to names, see resolveGroupNames.
func groupNames(gids []uint32) ([]string, error) {
	ids := make([]string, len(gids))
	for i, gid := range gids {
		ids[i] = strconv.FormatUint(uint64(gid), 10)
	}
	return resolveGroupNames(ids)
}
