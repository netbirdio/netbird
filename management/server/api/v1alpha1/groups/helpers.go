package groups

import (
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/apiv1alpha1"
)

func ToGroupsInfoMap(groups []*types.Group, idCount int) map[string][]apiv1alpha1.GroupMinimum {
	groupsInfoMap := make(map[string][]apiv1alpha1.GroupMinimum, idCount)
	groupsChecked := make(map[string]struct{}, len(groups)) // not sure why this is needed (left over from old implementation)
	for _, group := range groups {
		_, ok := groupsChecked[group.ID]
		if ok {
			continue
		}

		groupsChecked[group.ID] = struct{}{}
		for _, pk := range group.Peers {
			info := apiv1alpha1.GroupMinimum{
				Id:             group.ID,
				Name:           group.Name,
				PeersCount:     len(group.Peers),
				ResourcesCount: len(group.Resources),
			}
			groupsInfoMap[pk] = append(groupsInfoMap[pk], info)
		}
		for _, rk := range group.Resources {
			info := apiv1alpha1.GroupMinimum{
				Id:             group.ID,
				Name:           group.Name,
				PeersCount:     len(group.Peers),
				ResourcesCount: len(group.Resources),
			}
			groupsInfoMap[rk.ID] = append(groupsInfoMap[rk.ID], info)
		}
	}
	return groupsInfoMap
}
