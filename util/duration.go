package util

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

// Duration is used strictly for JSON requests/responses due to duration marshalling issues
type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		d.Duration = time.Duration(value)
		return nil
	case string:
		var err error
		d.Duration, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("invalid duration")
	}
}

func DurationFromEnv(key string, fallback time.Duration) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(val)
	if err != nil || parsed < 0 {
		log.Warnf("ignoring invalid %s value %q, using %v", key, val, fallback)
		return fallback
	}
	return parsed
}
