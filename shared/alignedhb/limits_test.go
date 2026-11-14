package alignedhb

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPeriodLimitsClamp(t *testing.T) {
	for _, l := range []PeriodLimits{{}, DefaultPeriodLimits()} {
		assert.Equal(t, 30*time.Second, l.Clamp(time.Second), "limits %+v: 1s is raised to 30s", l)
		assert.Equal(t, 300*time.Second, l.Clamp(1000*time.Second), "limits %+v: 1000s is lowered to 300s", l)
		assert.Equal(t, 60*time.Second, l.Clamp(60*time.Second), "limits %+v: 60s stays", l)
		assert.Equal(t, 30*time.Second, l.Clamp(0), "limits %+v: zero is raised to the minimum", l)
	}
	custom := PeriodLimits{Min: 45 * time.Second, Max: 90 * time.Second}
	assert.Equal(t, 45*time.Second, custom.Clamp(30*time.Second), "custom minimum")
	assert.Equal(t, 90*time.Second, custom.Clamp(120*time.Second), "custom maximum")
}

func TestPeriodLimitsValidate(t *testing.T) {
	assert.NoError(t, PeriodLimits{}.Validate(), "zero value means the defaults")
	assert.NoError(t, DefaultPeriodLimits().Validate(), "defaults")
	assert.NoError(t, PeriodLimits{Min: time.Minute, Max: time.Minute}.Validate(), "min equal to max")
	assert.NoError(t, PeriodLimits{Min: 45 * time.Second, Max: 120 * time.Second}.Validate(), "narrower range")
	for name, l := range map[string]PeriodLimits{
		"min zero":         {Max: time.Minute},
		"min 1s":           {Min: time.Second, Max: time.Minute},
		"min 10s":          {Min: 10 * time.Second, Max: MaxPeriod},
		"max 600s":         {Min: MinPeriod, Max: 600 * time.Second},
		"min 10s max 600s": {Min: 10 * time.Second, Max: 600 * time.Second},
		"min fractional":   {Min: 45500 * time.Millisecond, Max: time.Minute},
		"max fractional":   {Min: MinPeriod, Max: 45500 * time.Millisecond},
		"max below min":    {Min: 2 * time.Minute, Max: time.Minute},
	} {
		assert.Error(t, l.Validate(), "case %s", name)
	}
}

func TestClampAnswer(t *testing.T) {
	got, clamped := ClampAnswer(Answer{Period: time.Second, Phase: 500 * time.Millisecond})
	assert.True(t, clamped, "1s period")
	assert.Equal(t, Answer{Period: 30 * time.Second, Phase: 500 * time.Millisecond}, got, "1s is raised to 30s, phase kept")

	got, clamped = ClampAnswer(Answer{Period: 1000 * time.Second, Phase: 400 * time.Second})
	assert.True(t, clamped, "1000s period")
	assert.Equal(t, Answer{Period: 300 * time.Second, Phase: 100 * time.Second}, got, "1000s is lowered to 300s, phase folded into it")
	assert.True(t, ValidPhase(got.Phase, got.Period), "folded phase is valid")

	ok := Answer{Period: time.Minute, Phase: 12345 * time.Millisecond}
	got, clamped = ClampAnswer(ok)
	assert.False(t, clamped, "60s period")
	assert.Equal(t, ok, got, "60s stays as it is")

	got, clamped = ClampAnswer(Answer{Period: time.Minute, Phase: 75 * time.Second})
	assert.True(t, clamped, "phase past the period")
	assert.Equal(t, Answer{Period: time.Minute, Phase: 15 * time.Second}, got, "phase past the period is folded")
}
