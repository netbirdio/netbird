package elevate

import "strings"

// noOutput stands in for a process that said nothing, so that a report of what it
// said still reads as a sentence.
const noOutput = "no output"

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return noOutput
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
