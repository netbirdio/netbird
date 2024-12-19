package connprofile

import "github.com/netbirdio/netbird/client/iface/configurer"

type wgIface interface {
	GetAllStat() (map[string]configurer.WGStats, error)
}
