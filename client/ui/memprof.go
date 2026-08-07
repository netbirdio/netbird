//go:build !android && !ios && !freebsd && !js

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"
	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

// memProfOffsets are the snapshot times measured from application startup.
var memProfOffsets = []time.Duration{0, 2 * time.Minute, 5 * time.Minute}

// memProfMaxDepth bounds the child walk so a cycle in the reported parent links
// cannot spin forever.
const memProfMaxDepth = 4

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

// startMemProfiler dumps a profile snapshot at every memProfOffsets mark, each
// into its own timestamped directory under memProfBaseDir. The first runs once
// the application is up so the window inventory sees the eagerly created
// windows. Every failure is logged and never stops the GUI.
func startMemProfiler(app *application.App) {
	log.Infof("memory profiler enabled, writing to %s (snapshots at %v after startup)", memProfBaseDir(), memProfOffsets)

	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		go func() {
			started := time.Now()
			for _, offset := range memProfOffsets {
				if wait := time.Until(started.Add(offset)); wait > 0 {
					time.Sleep(wait)
				}
				writeMemProfile(app)
			}
		}()
	})
}

// memProfBaseDir returns the directory holding the snapshot directories.
func memProfBaseDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.TempDir(), "nbgui")
	}
	return "/tmp/nbgui"
}

// writeMemProfile creates a <timestamp>-<pid> directory and fills it with the
// runtime profiles, the memory statistics summary and the process tree.
func writeMemProfile(app *application.App) {
	name := fmt.Sprintf("%s-%d", time.Now().Format("20060102-150405"), os.Getpid())
	dir := filepath.Join(memProfBaseDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Warnf("create memory profile dir %s: %v", dir, err)
		return
	}

	// The heap profile reports live objects as of the last collection, so force
	// one to keep inuse_space from counting garbage that is already unreachable.
	runtime.GC()

	if err := writeMemStats(filepath.Join(dir, "memstats.txt"), app); err != nil {
		log.Warnf("write memory statistics: %v", err)
	}

	if err := writeProcTree(filepath.Join(dir, "proctree.txt")); err != nil {
		log.Warnf("write process tree: %v", err)
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
func writeMemStats(path string, app *application.App) error {
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
	fmt.Fprintf(&b, "\n")

	writeWindowInventory(&b, app)

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// writeWindowInventory lists the live Wails windows. A window that exists holds
// a webview process even while hidden, so this tells apart a leaked window (the
// count grows) from windows whose content grew (the count stays put).
func writeWindowInventory(b *strings.Builder, app *application.App) {
	windows := app.Window.GetAll()
	fmt.Fprintf(b, "windows:        %d\n", len(windows))
	for _, w := range windows {
		visible := "unknown"
		if ww, ok := w.(*application.WebviewWindow); ok {
			visible = strconv.FormatBool(ww.IsVisible())
		}
		fmt.Fprintf(b, "  id=%-3d name=%-20q visible=%-7s minimised=%-5t focused=%t\n",
			w.ID(), w.Name(), visible, w.IsMinimised(), w.IsFocused())
	}
}

// writeProcTree dumps this process and its descendants with their memory
// footprint. The webview runs in child processes whose memory the Go runtime
// profiles cannot see, so this is what attributes a footprint to a component.
func writeProcTree(path string) error {
	self, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		return fmt.Errorf("open own process: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "time: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "uptime: %s\n\n", time.Since(memProfStart).Round(time.Second))
	fmt.Fprintf(&b, "%-8s %-8s %-28s %12s %12s %12s %12s\n", "PID", "PPID", "NAME", "RSS", "VMS", "PSS", "PRIV_DIRTY")

	var totalRSS, totalPSS, totalPrivate uint64
	walkProcTree(&b, self, 0, &totalRSS, &totalPSS, &totalPrivate)

	fmt.Fprintf(&b, "\n%-8s %-8s %-28s %12s %12s %12s %12s\n", "", "", "TOTAL",
		formatKB(totalRSS), "", formatKB(totalPSS), formatKB(totalPrivate))
	fmt.Fprintf(&b, "\nPSS and PRIV_DIRTY come from /proc/<pid>/smaps_rollup and are Linux only.\n")

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// walkProcTree appends one line per process, depth-first, accumulating totals.
func walkProcTree(b *strings.Builder, p *process.Process, depth int, totalRSS, totalPSS, totalPrivate *uint64) {
	name, err := p.Name()
	if err != nil {
		name = "unknown"
	}

	var rss, vms uint64
	if info, err := p.MemoryInfo(); err == nil {
		rss, vms = info.RSS, info.VMS
	}

	pss, private := smapsRollup(p.Pid)
	*totalRSS += rss
	*totalPSS += pss
	*totalPrivate += private

	ppid, err := p.Ppid()
	if err != nil {
		ppid = -1
	}

	fmt.Fprintf(b, "%-8d %-8d %-28s %12s %12s %12s %12s\n", p.Pid, ppid,
		strings.Repeat("  ", depth)+name, formatKB(rss), formatKB(vms), formatKB(pss), formatKB(private))

	if depth >= memProfMaxDepth {
		return
	}

	children, err := p.Children()
	if err != nil {
		return
	}
	for _, child := range children {
		walkProcTree(b, child, depth+1, totalRSS, totalPSS, totalPrivate)
	}
}

// smapsRollup returns the proportional set size and private dirty bytes of pid,
// both zero on platforms without /proc.
func smapsRollup(pid int32) (uint64, uint64) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/smaps_rollup", pid))
	if err != nil {
		return 0, 0
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Debugf("close smaps_rollup for %d: %v", pid, err)
		}
	}()

	var pss, private uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "Pss:":
			pss = kb * 1024
		case "Private_Dirty:":
			private = kb * 1024
		}
	}
	return pss, private
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

// formatKB renders a byte count as megabytes for the process tree columns, and
// a dash when the platform did not report the value.
func formatKB(n uint64) string {
	if n == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
}
