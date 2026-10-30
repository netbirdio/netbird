package cmd

// startPprof starts the profiling listener of pprof-tagged builds. Its default
// address depends on the installation, so it runs once the installation is
// resolved; other builds leave it a no-op.
var startPprof = func() {}
