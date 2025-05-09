package conntype

import (
	"fmt"
)

const (
	None    ConnPriority = 0
	Relay   ConnPriority = 1
	ICETurn ConnPriority = 2
	ICEP2P  ConnPriority = 3
)

type ConnPriority int

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
