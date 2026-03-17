//go:build !pprof

package pprof

/*
Allow package build even without pprof tag.
Otherwise, Go complains that "build constraints exclude all Go files"
*/
