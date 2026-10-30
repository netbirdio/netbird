// Package instancecolor draws a named installation's colour on its tray icons,
// so two NetBird tray icons can be told apart.
package instancecolor

import (
	"fmt"
	"image/color"
	"strconv"
	"strings"
)

// Entry is one colour of the installer's palette.
type Entry struct {
	Name string
	Hex  string
}

// Palette is the Okabe-Ito set without black, which disappears on a dark
// taskbar. The order decides which colour the installer pre-selects: colours
// that cannot be mistaken for a tray state or the brand come first.
var Palette = []Entry{
	{"purple", "#CC79A7"},
	{"skyblue", "#56B4E9"},
	{"yellow", "#F0E442"},
	{"orange", "#E69F00"},
	{"blue", "#0072B2"},
	{"green", "#009E73"},
	{"vermillion", "#D55E00"},
}

// Parse accepts a palette name or a #RRGGBB value, in any case. The value comes
// from the installation record, which is untrusted input: anything else is
// rejected, and the caller then draws no colour.
func Parse(s string) (color.NRGBA, error) {
	s = strings.TrimSpace(s)
	for _, e := range Palette {
		if strings.EqualFold(s, e.Name) {
			s = e.Hex
			break
		}
	}
	if len(s) != 7 || s[0] != '#' {
		return color.NRGBA{}, fmt.Errorf("colour %q is not #RRGGBB or a palette name", s)
	}
	v, err := strconv.ParseUint(s[1:], 16, 32)
	if err != nil {
		return color.NRGBA{}, fmt.Errorf("colour %q is not #RRGGBB or a palette name", s)
	}
	return color.NRGBA{R: uint8(v >> 16), G: uint8(v >> 8), B: uint8(v), A: 0xff}, nil
}

// Hex formats an opaque colour as #RRGGBB, the form Parse accepts.
func Hex(c color.NRGBA) string {
	return fmt.Sprintf("#%02X%02X%02X", c.R, c.G, c.B)
}
