package main

import (
	"bytes"
	"strings"
	"testing"
)

func feed(t *testing.T, events string) string {
	t.Helper()
	var out bytes.Buffer
	s := newSummarizer(&out)
	if err := s.consume(strings.NewReader(events)); err != nil {
		t.Fatalf("consume: %v", err)
	}
	s.printSummary(10)
	return out.String()
}

func TestTimeoutReportsUnfinishedTestsAndPanicHead(t *testing.T) {
	events := `
{"Action":"run","Package":"a","Test":"TestHang"}
{"Action":"output","Package":"a","Test":"TestHang","Output":"=== RUN   TestHang\n"}
{"Action":"run","Package":"a","Test":"TestSilent"}
{"Action":"output","Package":"a","Test":"TestHang","Output":"panic: test timed out after 1s\n"}
{"Action":"output","Package":"a","Test":"TestHang","Output":"\trunning tests:\n"}
{"Action":"output","Package":"a","Test":"TestHang","Output":"\t\tTestHang (1s)\n"}
{"Action":"output","Package":"a","Test":"TestHang","Output":"goroutine 7 [running]:\n"}
{"Action":"fail","Package":"a","Elapsed":1.0}
`
	got := feed(t, events)
	for _, want := range []string{
		"--- UNFINISHED: a.TestHang",
		"--- UNFINISHED: a.TestSilent",
		"==== panic in a (first 4 lines) ====",
		"\t\tTestHang (1s)",
		"    === RUN   TestHang",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "    goroutine 7 [running]:") {
		t.Errorf("goroutine dump leaked into the test's own output:\n%s", got)
	}
}

func TestPanicInOnePackageKeepsOtherPackageOutput(t *testing.T) {
	events := `
{"Action":"run","Package":"a","Test":"TestHang"}
{"Action":"output","Package":"a","Test":"TestHang","Output":"panic: test timed out after 1s\n"}
{"Action":"run","Package":"b","Test":"TestOther"}
{"Action":"output","Package":"b","Test":"TestOther","Output":"    other_test.go:9: expected 1, got 2\n"}
{"Action":"output","Package":"a","Test":"TestHang","Output":"goroutine 7 [running]:\n"}
{"Action":"fail","Package":"b","Test":"TestOther","Elapsed":0.01}
{"Action":"fail","Package":"b","Elapsed":0.02}
{"Action":"fail","Package":"a","Elapsed":1.0}
`
	got := feed(t, events)
	if !strings.Contains(got, "    other_test.go:9: expected 1, got 2") {
		t.Errorf("other package's output was swallowed by the panic head:\n%s", got)
	}
	if strings.Contains(got, "panic in b") {
		t.Errorf("panic head attributed to the wrong package:\n%s", got)
	}
	if !strings.Contains(got, "==== panic in a (first 2 lines) ====") {
		t.Errorf("panic head missing for package a:\n%s", got)
	}
}

func TestStoreSetupTimeIsAttributedToTheTest(t *testing.T) {
	events := `
{"Action":"run","Package":"a","Test":"TestStore"}
{"Action":"output","Package":"a","Test":"TestStore","Output":"level=info msg=\"test store created: engine=mysql total=1.5s sqlite=100ms engine_setup=1.4s\"\n"}
{"Action":"output","Package":"a","Test":"TestStore","Output":"level=info msg=\"test store created: engine=mysql total=500ms sqlite=100ms engine_setup=400ms\"\n"}
{"Action":"pass","Package":"a","Test":"TestStore","Elapsed":2.5}
{"Action":"pass","Package":"a","Elapsed":2.6}
`
	got := feed(t, events)
	if !strings.Contains(got, "a.TestStore  [stores: 2, 2s]") {
		t.Errorf("store setup not aggregated:\n%s", got)
	}
}

func TestBuildFailureShowsCompilerOutput(t *testing.T) {
	// The event sequence go test emits for a build failure: the build events
	// name the test binary, then the package itself fails with FailedBuild.
	events := `
{"Action":"build-output","ImportPath":"a [a.test]","Output":"# a [a.test]\na_test.go:7:2: undefined: nope\na_test.go:9:2: undefined: nope2\n"}
{"Action":"build-fail","ImportPath":"a [a.test]"}
{"Action":"start","Package":"a"}
{"Action":"output","Package":"a","Output":"FAIL\ta [build failed]\n"}
{"Action":"fail","Package":"a","Elapsed":0,"FailedBuild":"a [a.test]"}
`
	got := feed(t, events)
	for _, want := range []string{
		"==== build output of a ====",
		"    a_test.go:7:2: undefined: nope\n    a_test.go:9:2: undefined: nope2",
		"FAIL\ta [build failed]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if n := strings.Count(got, "FAIL a 0s"); n != 1 {
		t.Errorf("expected one FAIL line for the package, got %d:\n%s", n, got)
	}
	if n := strings.Count(got, "undefined: nope2"); n != 1 {
		t.Errorf("expected the compiler output once, got %d:\n%s", n, got)
	}
}

func TestFailedDependencyOutputIsShownForEveryImporter(t *testing.T) {
	events := `
{"Action":"build-output","ImportPath":"m/x","Output":"# m/x\nx.go:3:11: undefined: y\n"}
{"Action":"build-fail","ImportPath":"m/x"}
{"Action":"start","Package":"m/a"}
{"Action":"output","Package":"m/a","Output":"FAIL\tm/a [build failed]\n"}
{"Action":"fail","Package":"m/a","Elapsed":0,"FailedBuild":"m/x"}
{"Action":"start","Package":"m/b"}
{"Action":"output","Package":"m/b","Output":"FAIL\tm/b [build failed]\n"}
{"Action":"fail","Package":"m/b","Elapsed":0,"FailedBuild":"m/x"}
`
	got := feed(t, events)
	if n := strings.Count(got, "x.go:3:11: undefined: y"); n != 2 {
		t.Errorf("expected the dependency's compiler output under both packages, got %d:\n%s", n, got)
	}
	if strings.Contains(got, "FAIL m/x") {
		t.Errorf("the dependency must not be reported as a package of its own:\n%s", got)
	}
}

func TestBuildFailureWithoutPackageEventIsStillReported(t *testing.T) {
	events := `
{"Action":"build-output","ImportPath":"a [a.test]","Output":"a_test.go:7:2: undefined: nope\n"}
{"Action":"build-fail","ImportPath":"a [a.test]"}
`
	got := feed(t, events)
	for _, want := range []string{"FAIL a [build failed]", "==== build output of a ====", "undefined: nope"} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
}

func TestCompilerPanicIsBuildOutputNotTestPanic(t *testing.T) {
	events := `
{"Action":"build-output","ImportPath":"a [a.test]","Output":"# a [a.test]\npanic: internal compiler error\n\ngoroutine 1 [running]:\n"}
{"Action":"build-fail","ImportPath":"a [a.test]"}
{"Action":"start","Package":"a"}
{"Action":"output","Package":"a","Output":"FAIL\ta [build failed]\n"}
{"Action":"fail","Package":"a","Elapsed":0,"FailedBuild":"a [a.test]"}
`
	got := feed(t, events)
	if !strings.Contains(got, "==== build output of a ====\n    # a [a.test]\n    panic: internal compiler error") {
		t.Errorf("compiler diagnostic missing from the build output block:\n%s", got)
	}
	if strings.Contains(got, "==== panic in") {
		t.Errorf("compiler output must not be reported as a test panic:\n%s", got)
	}
}

func TestBuildVariantsOfOnePackageKeepSeparateOutput(t *testing.T) {
	events := `
{"Action":"build-output","ImportPath":"a [a.test]","Output":"a.go:1:1: broken for a.test\n"}
{"Action":"build-output","ImportPath":"a [b.test]","Output":"a.go:1:1: broken for b.test\n"}
{"Action":"build-fail","ImportPath":"a [a.test]"}
{"Action":"build-fail","ImportPath":"a [b.test]"}
{"Action":"start","Package":"a"}
{"Action":"fail","Package":"a","Elapsed":0,"FailedBuild":"a [a.test]"}
{"Action":"start","Package":"b"}
{"Action":"fail","Package":"b","Elapsed":0,"FailedBuild":"a [b.test]"}
`
	got := feed(t, events)
	if strings.Count(got, "==== build output of a ====") != 2 {
		t.Errorf("expected one output block per build variant:\n%s", got)
	}
	for _, want := range []string{"broken for a.test", "broken for b.test"} {
		if strings.Count(got, want) != 1 {
			t.Errorf("expected %q exactly once:\n%s", want, got)
		}
	}
}

func TestPassingPackageOutputIsNotPrinted(t *testing.T) {
	events := `
{"Action":"output","Package":"a","Output":"level=info msg=\"noise between tests\"\n"}
{"Action":"pass","Package":"a","Elapsed":0.5}
`
	got := feed(t, events)
	if strings.Contains(got, "noise between tests") {
		t.Errorf("package output of a passing package should stay quiet:\n%s", got)
	}
}
