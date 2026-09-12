// Package main turns a `go test -json` stream into a readable CI log.
//
// It prints one line per top-level test as it finishes, the captured output of
// every failed test, the head of a package-level panic (which is where Go
// reports "test timed out" and the list of still-running tests), and ends with
// the per-package durations and the slowest tests. The exit code is always zero
// unless the input cannot be read; the `go test` exit code is what CI should act
// on, so run the two with `set -o pipefail`.
//
// Usage:
//
//	go test -json ./... | go run ./tools/gotestsummary
//	go run ./tools/gotestsummary -slowest 60 test-output.jsonl
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	modulePrefix = "github.com/netbirdio/netbird/"

	// failedTestOutputLines bounds how much captured output a single failed
	// test may print, so one noisy failure cannot flood the job log.
	failedTestOutputLines = 200
	// panicHeadLines is enough for the "panic: test timed out" header, the
	// "running tests:" list, and the first few goroutines of the dump.
	panicHeadLines = 150
	// bufferedOutputLines bounds the per-test output kept in memory while the
	// test runs; only the tail is kept once the cap is reached.
	bufferedOutputLines = 400
)

var storeCreatedRe = regexp.MustCompile(`test store created: engine=(\S+) total=(\S+)`)

type event struct {
	Action  string  `json:"Action"`
	Package string  `json:"Package"`
	Test    string  `json:"Test"`
	Output  string  `json:"Output"`
	Elapsed float64 `json:"Elapsed"`
}

type testKey struct {
	pkg, name string
}

type testResult struct {
	pkg, name  string
	action     string
	elapsed    time.Duration
	storeCount int
	storeTotal time.Duration
}

type packageResult struct {
	pkg     string
	action  string
	elapsed time.Duration
}

type summarizer struct {
	out io.Writer

	output    map[testKey][]string
	dropped   map[testKey]int
	stores    map[testKey]storeStats
	tests     []testResult
	packages  []packageResult
	panicHead []string
	panicking bool
}

type storeStats struct {
	count int
	total time.Duration
}

func newSummarizer(out io.Writer) *summarizer {
	return &summarizer{
		out:     out,
		output:  make(map[testKey][]string),
		dropped: make(map[testKey]int),
		stores:  make(map[testKey]storeStats),
	}
}

func main() {
	slowest := flag.Int("slowest", 40, "number of slowest top-level tests to list")
	flag.Parse()

	if err := run(flag.Arg(0), *slowest); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path string, slowest int) error {
	in := os.Stdin
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()
		in = f
	}

	s := newSummarizer(os.Stdout)
	if err := s.consume(in); err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	s.printSummary(slowest)
	return nil
}

func (s *summarizer) consume(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		var ev event
		if err := json.Unmarshal(line, &ev); err != nil {
			// Build errors and other non-JSON lines are passed through untouched.
			fmt.Fprintln(s.out, string(line))
			continue
		}
		s.handle(ev)
	}
	return scanner.Err()
}

func (s *summarizer) handle(ev event) {
	key := testKey{pkg: ev.Package, name: ev.Test}
	switch ev.Action {
	case "output":
		s.handleOutput(key, strings.TrimRight(ev.Output, "\n"))
	case "pass", "fail", "skip":
		if ev.Test == "" {
			s.handlePackageResult(ev)
			return
		}
		s.handleTestResult(key, ev)
	}
}

func (s *summarizer) handleOutput(key testKey, line string) {
	if strings.HasPrefix(line, "panic: ") || strings.HasPrefix(line, "fatal error: ") {
		s.panicking = true
	}
	if s.panicking {
		// The goroutine dump that follows a panic is kept in panicHead only;
		// letting it flood the per-test buffers would hide the test's own output.
		if len(s.panicHead) < panicHeadLines {
			s.panicHead = append(s.panicHead, line)
		}
		return
	}

	if m := storeCreatedRe.FindStringSubmatch(line); m != nil {
		if d, err := time.ParseDuration(m[2]); err == nil {
			st := s.stores[key]
			st.count++
			st.total += d
			s.stores[key] = st
		}
	}

	if key.name == "" {
		return
	}
	buf := s.output[key]
	if len(buf) >= bufferedOutputLines {
		buf = buf[1:]
		s.dropped[key]++
	}
	s.output[key] = append(buf, line)
}

func (s *summarizer) handleTestResult(key testKey, ev event) {
	elapsed := time.Duration(ev.Elapsed * float64(time.Second))
	st := s.stores[key]
	s.tests = append(s.tests, testResult{
		pkg:        ev.Package,
		name:       ev.Test,
		action:     ev.Action,
		elapsed:    elapsed,
		storeCount: st.count,
		storeTotal: st.total,
	})

	if !strings.Contains(ev.Test, "/") || ev.Action == "fail" {
		fmt.Fprintf(s.out, "--- %s: %s.%s (%s)\n", strings.ToUpper(ev.Action), shortPkg(ev.Package), ev.Test, elapsed.Round(time.Millisecond))
	}
	if ev.Action == "fail" {
		s.printTestOutput(key)
	}
	delete(s.output, key)
	delete(s.dropped, key)
}

func (s *summarizer) printTestOutput(key testKey) {
	lines := s.output[key]
	if len(lines) == 0 {
		return
	}
	skipped := s.dropped[key]
	if len(lines) > failedTestOutputLines {
		skipped += len(lines) - failedTestOutputLines
		lines = lines[len(lines)-failedTestOutputLines:]
	}
	if skipped > 0 {
		fmt.Fprintf(s.out, "    ... %d earlier output lines omitted ...\n", skipped)
	}
	for _, l := range lines {
		fmt.Fprintf(s.out, "    %s\n", l)
	}
}

func (s *summarizer) handlePackageResult(ev event) {
	elapsed := time.Duration(ev.Elapsed * float64(time.Second))
	s.packages = append(s.packages, packageResult{pkg: ev.Package, action: ev.Action, elapsed: elapsed})

	label := "ok  "
	switch ev.Action {
	case "fail":
		label = "FAIL"
	case "skip":
		label = "skip"
	}
	fmt.Fprintf(s.out, "%s %s %s\n", label, shortPkg(ev.Package), elapsed.Round(time.Millisecond))

	if ev.Action == "fail" {
		s.printUnfinished(ev.Package)
	}
	if ev.Action == "fail" && len(s.panicHead) > 0 {
		fmt.Fprintf(s.out, "\n==== panic in %s (first %d lines) ====\n", shortPkg(ev.Package), len(s.panicHead))
		for _, l := range s.panicHead {
			fmt.Fprintln(s.out, l)
		}
		fmt.Fprintln(s.out, "==== end of panic head ====")
		fmt.Fprintln(s.out)
		s.panicHead = nil
		s.panicking = false
	}
}

// printUnfinished names the tests of a failed package that never reported a
// result, which is what a timeout leaves behind, and shows their last output.
func (s *summarizer) printUnfinished(pkg string) {
	var keys []testKey
	for key := range s.output {
		if key.pkg == pkg && key.name != "" {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].name < keys[j].name })
	fmt.Fprintf(s.out, "\n==== tests in %s that did not finish (%d) ====\n", shortPkg(pkg), len(keys))
	for _, key := range keys {
		fmt.Fprintf(s.out, "--- UNFINISHED: %s.%s\n", shortPkg(key.pkg), key.name)
		s.printTestOutput(key)
		delete(s.output, key)
		delete(s.dropped, key)
	}
}

func (s *summarizer) printSummary(slowest int) {
	fmt.Fprintln(s.out)
	fmt.Fprintln(s.out, "==== package durations ====")
	sort.Slice(s.packages, func(i, j int) bool { return s.packages[i].elapsed > s.packages[j].elapsed })
	for _, p := range s.packages {
		fmt.Fprintf(s.out, "%9s  %-4s  %s\n", p.elapsed.Round(time.Millisecond), p.action, shortPkg(p.pkg))
	}

	var failed []testResult
	for _, t := range s.tests {
		if t.action == "fail" {
			failed = append(failed, t)
		}
	}
	if len(failed) > 0 {
		fmt.Fprintln(s.out)
		fmt.Fprintf(s.out, "==== failed tests (%d) ====\n", len(failed))
		for _, t := range failed {
			fmt.Fprintf(s.out, "%9s  %s.%s\n", t.elapsed.Round(time.Millisecond), shortPkg(t.pkg), t.name)
		}
	}

	s.printSlowest("slowest top-level tests", slowest, func(t testResult) bool { return !strings.Contains(t.name, "/") })
	s.printSlowest("slowest subtests", slowest/2, func(t testResult) bool { return strings.Contains(t.name, "/") })
}

func (s *summarizer) printSlowest(title string, limit int, keep func(testResult) bool) {
	var tests []testResult
	for _, t := range s.tests {
		if keep(t) {
			tests = append(tests, t)
		}
	}
	if len(tests) == 0 || limit <= 0 {
		return
	}
	sort.Slice(tests, func(i, j int) bool { return tests[i].elapsed > tests[j].elapsed })
	if len(tests) > limit {
		tests = tests[:limit]
	}

	fmt.Fprintln(s.out)
	fmt.Fprintf(s.out, "==== %s (%d) ====\n", title, len(tests))
	for _, t := range tests {
		line := fmt.Sprintf("%9s  %-4s  %s.%s", t.elapsed.Round(time.Millisecond), t.action, shortPkg(t.pkg), t.name)
		if t.storeCount > 0 {
			line += fmt.Sprintf("  [stores: %d, %s]", t.storeCount, t.storeTotal.Round(time.Millisecond))
		}
		fmt.Fprintln(s.out, line)
	}
}

func shortPkg(pkg string) string {
	return strings.TrimPrefix(pkg, modulePrefix)
}
