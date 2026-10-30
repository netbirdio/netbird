package instancecolor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// windowsTrayIcons are the colored tray PNGs the Windows UI uses, every state
// and theme variant.
var windowsTrayIcons = []string{
	"connected", "connected-dark", "connecting", "connecting-dark", "disconnected",
	"error", "error-dark", "needs-login", "update-connected", "update-connected-dark",
	"update-disconnected", "update-disconnected-dark",
}

func loadIcon(t *testing.T, state string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "assets", "netbird-systemtray-"+state+".png"))
	require.NoError(t, err)
	return b
}

func decodeNRGBA(t *testing.T, b []byte) *image.NRGBA {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(b))
	require.NoError(t, err)
	out := image.NewNRGBA(img.Bounds())
	draw.Draw(out, out.Bounds(), img, img.Bounds().Min, draw.Src)
	return out
}

// T-COL-02: the dot sits in the top-left corner of every state and theme, in
// the installation colour with a contrasting ring, and nothing else changes.
func TestOverlayEveryTrayIcon(t *testing.T) {
	fill, err := Parse("orange")
	require.NoError(t, err)

	for _, state := range windowsTrayIcons {
		for ringName, ring := range map[string]color.NRGBA{"light-taskbar": RingOnLight, "dark-taskbar": RingOnDark} {
			t.Run(state+"/"+ringName, func(t *testing.T) {
				srcBytes := loadIcon(t, state)
				out, err := Overlay(srcBytes, fill, ring)
				require.NoError(t, err)

				src, got := decodeNRGBA(t, srcBytes), decodeNRGBA(t, out)
				require.Equal(t, src.Bounds(), got.Bounds(), "native size kept")
				w := src.Bounds().Dx()
				dot := DotBounds(src.Bounds())
				assert.Equal(t, image.Pt(0, 0), dot.Min, "dot in the top-left corner")
				assert.LessOrEqual(t, dot.Max.X, w*53/100, "dot about 52%% of the width with its ring")

				changedOutside := 0
				for y := 0; y < src.Bounds().Dy(); y++ {
					for x := 0; x < w; x++ {
						if !image.Pt(x, y).In(dot) && src.NRGBAAt(x, y) != got.NRGBAAt(x, y) {
							changedOutside++
						}
					}
				}
				assert.Zero(t, changedOutside, "pixels outside the dot changed")

				centre := int(math.Round(float64(w) * (dotFraction/2 + ringFraction)))
				assert.Equal(t, fill, got.NRGBAAt(centre, centre), "dot colour at the centre")
				ringAt := centre - int(float64(w)*(dotFraction/2+ringFraction/2))
				assert.Equal(t, ring, got.NRGBAAt(centre, ringAt), "ring colour above the dot")
			})
		}
	}
}

// SBS-COL-04: Windows crops a notification logo to the inscribed circle, so the
// whole dot and ring must lie inside it; the logo is otherwise unchanged.
func TestNotificationLogoFitsTheCircle(t *testing.T) {
	fill, err := Parse("#E69F00")
	require.NoError(t, err)
	srcBytes, err := os.ReadFile(filepath.Join("..", "assets", "netbird.png"))
	require.NoError(t, err)

	out, err := NotificationLogo(srcBytes, fill, RingOnDark)
	require.NoError(t, err)
	src, got := decodeNRGBA(t, srcBytes), decodeNRGBA(t, out)
	require.Equal(t, src.Bounds(), got.Bounds(), "native size kept")

	w := src.Bounds().Dx()
	half := float64(w) / 2
	changed, outside := 0, 0
	for y := 0; y < w; y++ {
		for x := 0; x < w; x++ {
			if src.NRGBAAt(x, y) == got.NRGBAAt(x, y) {
				continue
			}
			changed++
			if math.Hypot(float64(x)+0.5-half, float64(y)+0.5-half) > half {
				outside++
			}
		}
	}
	assert.Positive(t, changed, "a dot is drawn")
	assert.Zero(t, outside, "pixels changed outside the crop circle")

	outer := float64(w) * (dotFraction/2 + ringFraction)
	centre := int(math.Round(half - (half-outer-1)/math.Sqrt2))
	assert.Equal(t, fill, got.NRGBAAt(centre, centre), "dot colour at its centre")
	ringAt := centre - int(float64(w)*(dotFraction/2+ringFraction/2))
	assert.Equal(t, RingOnDark, got.NRGBAAt(centre, ringAt), "ring colour above the dot")
}

// TestOverlayGolden pins the composited pixels, so a change of the drawing is
// a deliberate one.
func TestOverlayGolden(t *testing.T) {
	fill, err := Parse("#E69F00")
	require.NoError(t, err)

	got := map[string]string{}
	for _, state := range windowsTrayIcons {
		ring := RingOnLight
		if strings.HasSuffix(state, "-dark") {
			ring = RingOnDark
		}
		out, err := Overlay(loadIcon(t, state), fill, ring)
		require.NoError(t, err)
		sum := sha256.Sum256(decodeNRGBA(t, out).Pix)
		got[state] = hex.EncodeToString(sum[:8])
	}
	assert.Equal(t, goldenOverlays, got, "composited icons")
}

func TestParse(t *testing.T) {
	for _, e := range Palette {
		c, err := Parse(e.Name)
		require.NoError(t, err, e.Name)
		c2, err := Parse(strings.ToLower(e.Hex))
		require.NoError(t, err, e.Hex)
		assert.Equal(t, c, c2, "name and hex of %s", e.Name)
	}
	c, err := Parse("#E8A33D")
	require.NoError(t, err)
	assert.Equal(t, color.NRGBA{R: 0xe8, G: 0xa3, B: 0x3d, A: 0xff}, c, "custom colour")
	assert.Equal(t, "#E8A33D", Hex(c), "formatted as Parse accepts it")
	for _, e := range Palette {
		c, err := Parse(e.Name)
		require.NoError(t, err, e.Name)
		assert.Equal(t, e.Hex, Hex(c), "hex of %s", e.Name)
	}

	for _, bad := range []string{"", "#12345", "#1234567", "E8A33D", "#GGGGGG", "red", "#E8A33D;", "url(x)"} {
		_, err := Parse(bad)
		assert.Error(t, err, "colour %q", bad)
	}
}

// goldenOverlays holds the first 8 bytes of the SHA-256 of each composited
// icon's pixels, orange dot. error and needs-login share their source image.
var goldenOverlays = map[string]string{
	"connected":                "5e5bae2a95a0b0ad",
	"connected-dark":           "be57764dd20b5605",
	"connecting":               "ce2745a4aa33e715",
	"connecting-dark":          "b150169df151a9ae",
	"disconnected":             "3a65b319ec404ac1",
	"error":                    "772f8ca4dbba9609",
	"error-dark":               "af0d956c3b6f4da8",
	"needs-login":              "772f8ca4dbba9609",
	"update-connected":         "6815efefc1815315",
	"update-connected-dark":    "a373a44acc37213a",
	"update-disconnected":      "97fc81cad2b7e2cb",
	"update-disconnected-dark": "36ba57eaf641bdd4",
}
