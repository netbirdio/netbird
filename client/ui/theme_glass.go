package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// GlassTheme implements a custom Fyne theme with icy blue glass aesthetic
type GlassTheme struct{}

var _ fyne.Theme = (*GlassTheme)(nil)

// Modern icy blue color palette with better contrast
var (
	icyBlue       = color.NRGBA{R: 163, G: 215, B: 229, A: 255} // #a3d7e5
	icyBlueDark   = color.NRGBA{R: 140, G: 200, B: 215, A: 255}
	icyBlueLight  = color.NRGBA{R: 200, G: 235, B: 245, A: 255}
	icyBlueAlpha  = color.NRGBA{R: 163, G: 215, B: 229, A: 77}  // 0.3 opacity

	// Darker, more sophisticated backgrounds
	darkBg        = color.NRGBA{R: 18, G: 18, B: 24, A: 255}    // Solid for modern look
	darkBgLight   = color.NRGBA{R: 24, G: 24, B: 30, A: 255}
	darkBgCard    = color.NRGBA{R: 28, G: 28, B: 35, A: 255}
	darkView      = color.NRGBA{R: 16, G: 16, B: 20, A: 255}

	textLight     = color.NRGBA{R: 248, G: 248, B: 252, A: 255}
	textMuted     = color.NRGBA{R: 160, G: 160, B: 170, A: 255}
	textDark      = color.NRGBA{R: 10, G: 10, B: 15, A: 255}

	borderColor   = color.NRGBA{R: 163, G: 215, B: 229, A: 20}  // Subtle icy blue border

	errorRed      = color.NRGBA{R: 239, G: 68, B: 68, A: 255}   // Modern vibrant red
	warningYellow = color.NRGBA{R: 251, G: 191, B: 36, A: 255}  // Modern vibrant yellow
	successGreen  = color.NRGBA{R: 34, G: 197, B: 94, A: 255}   // Modern vibrant green
)

func (g *GlassTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	// We only support dark variant for the glass theme
	switch name {
	// Primary colors
	case theme.ColorNamePrimary:
		return icyBlue

	// Background colors
	case theme.ColorNameBackground:
		return darkBg
	case theme.ColorNameOverlayBackground:
		return darkBgCard
	case theme.ColorNameMenuBackground:
		return darkBgCard
	case theme.ColorNameInputBackground:
		return darkView

	// Foreground/text colors
	case theme.ColorNameForeground:
		return textLight
	case theme.ColorNamePlaceHolder:
		return textMuted
	case theme.ColorNameDisabled:
		return textMuted

	// Button colors - more vibrant
	case theme.ColorNameButton:
		return icyBlue
	case theme.ColorNameHover:
		return icyBlueLight
	case theme.ColorNamePressed:
		return icyBlueDark
	case theme.ColorNameFocus:
		return icyBlue

	// Selection colors
	case theme.ColorNameSelection:
		return icyBlueAlpha

	// Border/separator colors
	case theme.ColorNameSeparator:
		return borderColor
	case theme.ColorNameInputBorder:
		return borderColor

	// Scrollbar
	case theme.ColorNameScrollBar:
		return color.NRGBA{R: 163, G: 215, B: 229, A: 51} // 0.2 opacity

	// Shadow (subtle for glass effect)
	case theme.ColorNameShadow:
		return color.NRGBA{R: 0, G: 0, B: 0, A: 51} // 0.2 opacity

	// Header/toolbar
	case theme.ColorNameHeaderBackground:
		return darkBgLight

	// Status colors
	case theme.ColorNameError:
		return errorRed
	case theme.ColorNameWarning:
		return warningYellow
	case theme.ColorNameSuccess:
		return successGreen

	// Hyperlinks
	case theme.ColorNameHyperlink:
		return icyBlueLight

	default:
		// Fallback to default dark theme
		return theme.DefaultTheme().Color(name, theme.VariantDark)
	}
}

func (g *GlassTheme) Font(style fyne.TextStyle) fyne.Resource {
	// Use default Fyne fonts but we could customize here if needed
	// Fyne uses Go's built-in fonts which are clean and modern
	return theme.DefaultTheme().Font(style)
}

func (g *GlassTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (g *GlassTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	// Increase padding for modern spacing
	case theme.SizeNamePadding:
		return 8
	case theme.SizeNameInlineIcon:
		return 24
	case theme.SizeNameScrollBar:
		return 12
	case theme.SizeNameScrollBarSmall:
		return 6
	case theme.SizeNameSeparatorThickness:
		return 1
	case theme.SizeNameInputBorder:
		return 2
	case theme.SizeNameInputRadius:
		return 8 // More rounded corners
	case theme.SizeNameSelectionRadius:
		return 8
	default:
		return theme.DefaultTheme().Size(name)
	}
}
