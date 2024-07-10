package main

import (
	"os"
	"path"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

func (s *serviceClient) setDefaultFonts() {
	defaultFontPath := s.getWindowsFontFilePath()

	if _, err := os.Stat(defaultFontPath); err != nil {
		log.Errorf("Failed to find default font file: %v", err)
		return
	}

	os.Setenv("FYNE_FONT", defaultFontPath)
}

func (s *serviceClient) getWindowsFontFilePath() (fontPath string) {
	var (
		fontFolder  = "C:/Windows/Fonts"
		fontMapping = map[string]string{
			"default":     "Segoeui.ttf",
			"zh-CN":       "Msyh.ttc",
			"am-ET":       "Ebrima.ttf",
			"nirmala":     "Nirmala.ttf",
			"chr-CHER-US": "Gadugi.ttf",
			"zh-HK":       "Msjh.ttc",
			"zh-TW":       "Msjh.ttc",
			"ja-JP":       "Yugothm.ttc",
			"km-KH":       "Leelawui.ttf",
			"ko-KR":       "Malgun.ttf",
			"th-TH":       "Leelawui.ttf",
			"ti-ET":       "Ebrima.ttf",
		}
		nirMalaLang = []string{
			"as-IN",
			"bn-BD",
			"bn-IN",
			"gu-IN",
			"hi-IN",
			"kn-IN",
			"kok-IN",
			"ml-IN",
			"mr-IN",
			"ne-NP",
			"or-IN",
			"pa-IN",
			"si-LK",
			"ta-IN",
			"te-IN",
		}
	)

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getUserDefaultLocaleName := kernel32.NewProc("GetUserDefaultLocaleName")

	buf := make([]uint16, 85) // LOCALE_NAME_MAX_LENGTH is usually 85
	r, _, _ := getUserDefaultLocaleName.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r == 0 {
		log.Error("Failed to get Windows default language setting")
		fontPath = path.Join(fontFolder, fontMapping["default"])
		return
	}

	defaultLanguage := syscall.UTF16ToString(buf)

	for _, lang := range nirMalaLang {
		if defaultLanguage == lang {
			fontPath = path.Join(fontFolder, fontMapping["nirmala"])
			return
		}
	}

	if font, ok := fontMapping[defaultLanguage]; ok {
		fontPath = path.Join(fontFolder, font)
	} else {
		fontPath = path.Join(fontFolder, fontMapping["default"])
	}
	return
}
