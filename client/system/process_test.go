package system

import (
	"context"
	"testing"

	"github.com/shirou/gopsutil/v4/process"
)

func Benchmark_getRunningProcesses(b *testing.B) {
	b.Run("getRunningProcesses new", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ps, err := getRunningProcesses(context.Background())
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
	s, _ := getRunningProcesses(context.Background())
	b.Logf("getRunningProcesses returned %d processes", len(s))
	s, _ = getRunningProcessesOld()
	b.Logf("getRunningProcessesOld returned %d processes", len(s))
}

func TestCheckFileAndProcess_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// With a canceled context and non-empty paths the gathering must bail with an error
	// instead of running the (potentially blocking) process scan / stat loop.
	if _, err := checkFileAndProcess(ctx, []string{"/does/not/exist"}); err == nil {
		t.Fatal("expected error on canceled context, got nil")
	}
}

func TestCheckFileAndProcess_EmptyPaths(t *testing.T) {
	// No check paths means no work to do: it must return immediately with no error,
	// even on a canceled context (nothing to scan or stat).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	files, err := checkFileAndProcess(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error for empty paths: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected no files, got %d", len(files))
	}
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
