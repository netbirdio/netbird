package ice

import (
	"sync/atomic"

	"github.com/pion/stun/v3"
)

type StunTurn atomic.Value

func (s *StunTurn) Load() []*stun.URI {
	v := (*atomic.Value)(s).Load()
	if v == nil {
		return nil
	}

	return v.([]*stun.URI)
}

func (s *StunTurn) Store(value []*stun.URI) {
	(*atomic.Value)(s).Store(value)
}
