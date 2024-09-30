package configurer

import "time"

type WGStats struct {
	LastHandshake time.Time
	TxBytes       int64
	RxBytes       int64
}
