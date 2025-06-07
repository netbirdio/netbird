package system

import (
	"os"
	"slices"
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
	b.Run("getting PIDs only", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := process.Pids()
			if err != nil && !os.IsNotExist(err) && !slices.Contains([]string{"no such process", "process not found"}, err.Error()) {
				b.Fatalf("unexpected error when getting PIDs: %v", err)
			}
		}
	})
	pids, err := process.Pids()
	if err != nil {
		b.Fatalf("unexpected error when getting PIDs: %v", err)
	}
	b.Run("getting exe", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, pid := range pids {
				proc := &process.Process{Pid: pid}
				_, err := proc.Exe()
				if err != nil && !os.IsNotExist(err) && !slices.Contains([]string{"no such process", "process not found"}, err.Error()) {
					b.Fatalf("unexpected error when getting exe: %v", err)
				}
			}
		}
	})
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
