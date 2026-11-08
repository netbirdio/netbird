package testhb

import (
	"hash/fnv"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKey = "Zm9vYmFyYmF6cXV4cXV1eHF1dXhxdXV4cXV1eHF1dXg="

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func hashPhase(key string, periodMs int64) int64 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int64(h.Sum32()) % periodMs
}

func TestScheduleFromEnv(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		key  string
		want schedule
		ok   bool
	}{
		{"unset is stock", map[string]string{}, testKey, schedule{}, false},
		{"false is stock", map[string]string{EnvDynamic: "0"}, testKey, schedule{}, false},
		{"junk is stock", map[string]string{EnvDynamic: "yes please"}, testKey, schedule{}, false},
		{"default period", map[string]string{EnvDynamic: "1"}, testKey, schedule{phaseMs: hashPhase(testKey, 30000), periodSec: 30}, true},
		{"env period", map[string]string{EnvDynamic: "1", EnvPeriod: "10"}, testKey, schedule{phaseMs: hashPhase(testKey, 10000), periodSec: 10}, true},
		{"bad period uses default", map[string]string{EnvDynamic: "1", EnvPeriod: "-3"}, testKey, schedule{phaseMs: hashPhase(testKey, 30000), periodSec: 30}, true},
		{"phase override", map[string]string{EnvDynamic: "1", EnvPhase: "17342"}, testKey, schedule{phaseMs: 17342, periodSec: 30}, true},
		{"phase override without key", map[string]string{EnvDynamic: "1", EnvPhase: "0"}, "", schedule{phaseMs: 0, periodSec: 30}, true},
		{"phase override out of range uses hash", map[string]string{EnvDynamic: "1", EnvPeriod: "10", EnvPhase: "10000"}, testKey, schedule{phaseMs: hashPhase(testKey, 10000), periodSec: 10}, true},
		{"no key and no override", map[string]string{EnvDynamic: "true"}, "", schedule{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := scheduleFromEnv(envOf(tc.env), tc.key)
			assert.Equal(t, tc.ok, ok, "ok")
			assert.Equal(t, tc.want, got, "schedule")
		})
	}
}

func TestSchedulePhaseInRange(t *testing.T) {
	for i := 0; i < 1000; i++ {
		key := "key-" + strconv.Itoa(i)
		for _, period := range []string{"1", "7", "30"} {
			s, ok := scheduleFromEnv(envOf(map[string]string{EnvDynamic: "1", EnvPeriod: period}), key)
			require.True(t, ok)
			assert.True(t, s.phaseMs >= 0 && s.phaseMs < s.periodSec*1000, "key %q period %s: phase %d", key, period, s.phaseMs)
		}
	}
}

var valueRe = regexp.MustCompile(`^p=(\d+);period=(\d+);t=(\d+)$`)

func TestValueFormat(t *testing.T) {
	assert.Equal(t, "p=17342;period=30;t=1762600000123",
		schedule{phaseMs: 17342, periodSec: 30}.value(time.UnixMilli(1762600000123)), "contract example")

	t.Setenv(EnvDynamic, "1")
	t.Setenv(EnvPeriod, "30")
	t.Setenv(EnvPhase, "")
	before := time.Now().UnixMilli()
	v, ok := Value("signal", testKey)
	after := time.Now().UnixMilli()
	require.True(t, ok)
	m := valueRe.FindStringSubmatch(v)
	require.NotNil(t, m, "value %q", v)
	assert.Equal(t, strconv.FormatInt(hashPhase(testKey, 30000), 10), m[1], "phase")
	assert.Equal(t, "30", m[2], "period")
	ts, err := strconv.ParseInt(m[3], 10, 64)
	require.NoError(t, err)
	assert.True(t, ts >= before && ts <= after, "t=%d must be taken at the call", ts)
}

func TestValueStockWhenUnset(t *testing.T) {
	t.Setenv(EnvDynamic, "")
	require.NoError(t, os.Unsetenv(EnvDynamic))
	v, ok := Value("management", testKey)
	assert.False(t, ok, "unset switch must send nothing")
	assert.Empty(t, v, "unset switch must give no value")
}

func TestOwnKey(t *testing.T) {
	prev := OwnKey()
	t.Cleanup(func() { SetOwnKey(prev) })
	SetOwnKey(testKey)
	assert.Equal(t, testKey, OwnKey(), "own key")
}
