package conntype

import (
	"fmt"
	"sync/atomic"
)

const (
	None    ConnPriority = 0
	Relay   ConnPriority = 1
	ICETurn ConnPriority = 2
	ICEP2P  ConnPriority = 3
)

type ConnPriority int32

func (cp ConnPriority) String() string {
	switch cp {
	case None:
		return "None"
	case Relay:
		return "PriorityRelay"
	case ICETurn:
		return "PriorityICETurn"
	case ICEP2P:
		return "PriorityICEP2P"
	default:
		return fmt.Sprintf("ConnPriority(%d)", cp)
	}
}

type ConnPriorityStore struct {
	store atomic.Int32
}

func (cps *ConnPriorityStore) Get() ConnPriority {
	return ConnPriority(cps.store.Load())
}

func (cps *ConnPriorityStore) Set(cp ConnPriority) {
	cps.store.Store(int32(cp))
}
