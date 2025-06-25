package system

import (
	"testing"

	"github.com/shirou/gopsutil/v3/process"
)

func Benchmark_getRunningProcesses(b *testing.B) {
	b.Run("getRunningProcesses new", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ps, err := getRunningProcesses()
			if err != nil {
				b.Fatalf("unexpected error: %v", err)
			}
			if len(ps) == 0 {
				b.Fatalf("expected non-empty process list, got empty")
			}
		}
	})
	b.Run("getRunningProcesses old", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ps, err := getRunningProcessesOld()
			if err != nil {
				b.Fatalf("unexpected error: %v", err)
			}
			if len(ps) == 0 {
				b.Fatalf("expected non-empty process list, got empty")
			}
		}
	})
	s, _ := getRunningProcesses()
	b.Logf("getRunningProcesses returned %d processes", len(s))
	s, _ = getRunningProcessesOld()
	b.Logf("getRunningProcessesOld returned %d processes", len(s))
}

func getRunningProcessesOld() ([]string, error) {
	processes, err := process.Processes()
	if err != nil {
		return nil, err
	}

	processMap := make(map[string]bool)
	for _, p := range processes {
		path, _ := p.Exe()
		if path != "" {
			processMap[path] = true
		}
	}

	uniqueProcesses := make([]string, 0, len(processMap))
	for p := range processMap {
		uniqueProcesses = append(uniqueProcesses, p)
	}

	return uniqueProcesses, nil
}
