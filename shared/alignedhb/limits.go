package alignedhb

import (
	"fmt"
	"time"
)

// PeriodLimits bound the heartbeat period a server accepts. The zero value
// means the defaults, MinPeriod and MaxPeriod.
type PeriodLimits struct {
	Min time.Duration
	Max time.Duration
}

// DefaultPeriodLimits returns the limits servers use unless configured
// otherwise, and the limits clients always apply to server answers.
func DefaultPeriodLimits() PeriodLimits {
	return PeriodLimits{Min: MinPeriod, Max: MaxPeriod}
}

// Validate reports whether l can be used as server config: whole seconds
// inside MinPeriod to MaxPeriod, Max not below Min. Config may only narrow the
// default range, so it cannot reopen a heartbeat clients refuse to follow. The
// zero value is valid.
func (l PeriodLimits) Validate() error {
	if l == (PeriodLimits{}) {
		return nil
	}
	switch {
	case l.Min < MinPeriod || l.Min%time.Second != 0:
		return fmt.Errorf("min period %s: must be whole seconds, at least %s", l.Min, MinPeriod)
	case l.Max > MaxPeriod || l.Max%time.Second != 0:
		return fmt.Errorf("max period %s: must be whole seconds, at most %s", l.Max, MaxPeriod)
	case l.Max < l.Min:
		return fmt.Errorf("max period %s below min period %s", l.Max, l.Min)
	default:
		return nil
	}
}

// Clamp returns period limited to l. A server uses the result as the period it
// confirms and sends on, so a client cannot ask for a heartbeat that floods it
// or one so rare that its streams time out.
func (l PeriodLimits) Clamp(period time.Duration) time.Duration {
	if l == (PeriodLimits{}) {
		l = DefaultPeriodLimits()
	}
	return min(max(period, l.Min), l.Max)
}

// ClampAnswer returns a with the period limited to the default period limits
// and the phase folded into that period. A client applies it to what a server
// sends, so a buggy or hostile server cannot make the device wake every
// second. clamped is true when a changed.
func ClampAnswer(a Answer) (_ Answer, clamped bool) {
	period := DefaultPeriodLimits().Clamp(a.Period)
	phase := a.Phase.Truncate(time.Millisecond) % period
	if phase < 0 {
		phase += period
	}
	out := Answer{Period: period, Phase: phase}
	return out, out != a
}
