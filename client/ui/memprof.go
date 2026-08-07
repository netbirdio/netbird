//go:build !android && !ios && !freebsd && !js

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"
	log "github.com/sirupsen/logrus"
)

const memProfDelay = 5 * time.Minute

type memProfileSpec struct {
	profile string
	file    string
	debug   int
}

var memProfileSpecs = []memProfileSpec{
	{profile: "heap", file: "heap.pprof", debug: 0},
	{profile: "heap", file: "heap.txt", debug: 1},
	{profile: "goroutine", file: "goroutine.txt", debug: 1},
	{profile: "threadcreate", file: "threadcreate.txt", debug: 1},
}

var memProfStart = time.Now()

// startMemProfiler dumps two profile snapshots for memory analysis: one at
// startup and one after memProfDelay, each into its own timestamped directory
// under memProfBaseDir. Every failure is logged and never stops the GUI.
func startMemProfiler() {
	base := memProfBaseDir()
	log.Infof("memory profiler enabled, writing to %s (snapshots at startup and after %s)", base, memProfDelay)

	go func() {
		writeMemProfile()
		time.Sleep(memProfDelay)
		writeMemProfile()
	}()
}

// memProfBaseDir returns the directory holding the snapshot directories.
func memProfBaseDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.TempDir(), "nbgui")
	}
	return "/tmp/nbgui"
}

// writeMemProfile creates a <timestamp>-<pid> directory and fills it with the
// runtime profiles and the memory statistics summary.
func writeMemProfile() {
	name := fmt.Sprintf("%s-%d", time.Now().Format("20060102-150405"), os.Getpid())
	dir := filepath.Join(memProfBaseDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Warnf("create memory profile dir %s: %v", dir, err)
		return
	}

	// The heap profile reports live objects as of the last collection, so force
	// one to keep inuse_space from counting garbage that is already unreachable.
	runtime.GC()

	if err := writeMemStats(filepath.Join(dir, "memstats.txt")); err != nil {
		log.Warnf("write memory statistics: %v", err)
	}

	for _, spec := range memProfileSpecs {
		if err := writeMemProfileFile(spec, filepath.Join(dir, spec.file)); err != nil {
			log.Warnf("write %s profile: %v", spec.profile, err)
		}
	}

	log.Infof("memory profile written to %s", dir)
}

// writeMemProfileFile writes a single runtime profile to path.
func writeMemProfileFile(spec memProfileSpec, path string) error {
	p := pprof.Lookup(spec.profile)
	if p == nil {
		return fmt.Errorf("unknown profile %q", spec.profile)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Debugf("close %s: %v", path, err)
		}
	}()

	if err := p.WriteTo(f, spec.debug); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// writeMemStats dumps the runtime memory statistics next to the process
// resident set size. A resident set much larger than Sys means the memory sits
// outside the Go heap (webview, GTK, other cgo allocations), where the pprof
// profiles cannot see it.
func writeMemStats(path string) error {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	var b strings.Builder
	fmt.Fprintf(&b, "time:           %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "uptime:         %s\n", time.Since(memProfStart).Round(time.Second))
	fmt.Fprintf(&b, "pid:            %d\n", os.Getpid())
	fmt.Fprintf(&b, "\n")

	rss, vms := processMemory()
	fmt.Fprintf(&b, "process_rss:    %s\n", rss)
	fmt.Fprintf(&b, "process_vms:    %s\n", vms)
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "sys:            %s\n", formatMemBytes(m.Sys))
	fmt.Fprintf(&b, "heap_alloc:     %s\n", formatMemBytes(m.HeapAlloc))
	fmt.Fprintf(&b, "heap_sys:       %s\n", formatMemBytes(m.HeapSys))
	fmt.Fprintf(&b, "heap_inuse:     %s\n", formatMemBytes(m.HeapInuse))
	fmt.Fprintf(&b, "heap_idle:      %s\n", formatMemBytes(m.HeapIdle))
	fmt.Fprintf(&b, "heap_released:  %s\n", formatMemBytes(m.HeapReleased))
	fmt.Fprintf(&b, "heap_objects:   %d\n", m.HeapObjects)
	fmt.Fprintf(&b, "stack_inuse:    %s\n", formatMemBytes(m.StackInuse))
	fmt.Fprintf(&b, "stack_sys:      %s\n", formatMemBytes(m.StackSys))
	fmt.Fprintf(&b, "mspan_sys:      %s\n", formatMemBytes(m.MSpanSys))
	fmt.Fprintf(&b, "mcache_sys:     %s\n", formatMemBytes(m.MCacheSys))
	fmt.Fprintf(&b, "gc_sys:         %s\n", formatMemBytes(m.GCSys))
	fmt.Fprintf(&b, "other_sys:      %s\n", formatMemBytes(m.OtherSys))
	fmt.Fprintf(&b, "next_gc:        %s\n", formatMemBytes(m.NextGC))
	fmt.Fprintf(&b, "num_gc:         %d\n", m.NumGC)
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "goroutines:     %d\n", runtime.NumGoroutine())
	fmt.Fprintf(&b, "cgo_calls:      %d\n", runtime.NumCgoCall())
	fmt.Fprintf(&b, "gomaxprocs:     %d\n", runtime.GOMAXPROCS(0))

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// processMemory returns the formatted resident and virtual size of this process.
func processMemory() (string, string) {
	p, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		unavailable := fmt.Sprintf("unavailable (%v)", err)
		return unavailable, unavailable
	}

	info, err := p.MemoryInfo()
	if err != nil {
		unavailable := fmt.Sprintf("unavailable (%v)", err)
		return unavailable, unavailable
	}

	return formatMemBytes(info.RSS), formatMemBytes(info.VMS)
}

// formatMemBytes renders a byte count as megabytes with the raw value kept.
func formatMemBytes(n uint64) string {
	return fmt.Sprintf("%8.1f MB (%d bytes)", float64(n)/(1024*1024), n)
}
