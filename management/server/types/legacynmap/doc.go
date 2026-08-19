// Package legacynmap is a frozen copy of main's Account → NetworkMapComponents
// → NetworkMap → proto path. It exists only to measure this tree against main:
// the proto-equivalence test runs it over a production database copy, and the
// nmaptest golden suite runs it as a third mode so every case pins all three
// shapes to one expectation.
//
// It lives in its own package so it cannot reach this tree's unexported
// helpers — a divergence can therefore never be hidden by the two sides
// sharing code. Nothing in production imports it.
//
// Types are aliased rather than copied where they are byte-identical between
// main and this branch. Anything that drifted is copied instead; see
// converters.go and copied_funcs.go.
//
// Delete this package once the nmdata refactor is validated.
package legacynmap
