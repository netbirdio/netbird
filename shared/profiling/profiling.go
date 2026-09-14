package profiling

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/caarlos0/env/v11"
	"github.com/grafana/pyroscope-go"
	log "github.com/sirupsen/logrus"
)

var errNotConfigured = errors.New("pyroscope not configured")

var started atomic.Bool

type config struct {
	Address  string `env:"NB_PYROSCOPE_ADDRESS"`
	User     string `env:"NB_PYROSCOPE_USER,notEmpty"`
	Password string `env:"NB_PYROSCOPE_PASSWORD,notEmpty"`
}

func Start(applicationName string) func() {
	noop := func() {}

	cfg, err := loadConfig()
	switch {
	case errors.Is(err, errNotConfigured):
		log.Info("pyroscope not configured, continuous profiling disabled")
		return noop
	case err != nil:
		log.Errorf("failed to load pyroscope config: %v", err)
		return noop
	}

	// pprof allows one CPU profile per process, so a second profiler (e.g. the
	// signal server inside the combined binary) would only log errors.
	if !started.CompareAndSwap(false, true) {
		log.Warnf("continuous profiling already running in this process, not starting it for %s", applicationName)
		return noop
	}

	tags := map[string]string{}
	if hostname, err := os.Hostname(); err == nil {
		tags["instance"] = hostname
	} else {
		log.Warnf("failed to resolve hostname for profile tags: %v", err)
	}

	profiler, err := pyroscope.Start(pyroscope.Config{
		ApplicationName:   applicationName,
		ServerAddress:     cfg.Address,
		BasicAuthUser:     cfg.User,
		BasicAuthPassword: cfg.Password,
		Logger:            log.StandardLogger(),
		Tags:              tags,
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileInuseObjects,
			pyroscope.ProfileInuseSpace,
		},
	})
	if err != nil {
		started.Store(false)
		log.Errorf("failed to start continuous profiling: %v", err)
		return noop
	}

	return func() {
		_ = profiler.Stop()
		started.Store(false)
	}
}

func loadConfig() (config, error) {
	var cfg config
	if err := env.Parse(&cfg); err != nil {
		if cfg.Address == "" {
			return cfg, errNotConfigured
		}
		return cfg, fmt.Errorf("failed to parse pyroscope config: %w", err)
	}

	if cfg.Address == "" {
		return cfg, errNotConfigured
	}

	return cfg, nil
}
