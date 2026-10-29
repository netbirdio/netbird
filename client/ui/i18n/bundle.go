//go:build !android && !ios && !freebsd && !js

// Package i18n loads and serves translation strings for both the tray (Go)
// and the React UI (via the services.I18n facade).
//
// The locale tree is passed in as an fs.FS so the embed directive can live in
// the main binary.
package i18n

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

const (
	localeIndexFile = "_index.json"

	// commonBundleFile shape is Chrome-extension JSON (key -> "message" plus
	// optional Crowdin "description"); loadBundle flattens to key->message.
	commonBundleFile = "common.json"
)

// LanguageCode is a BCP-47-ish locale identifier ("en", "hu", ...).
type LanguageCode string

// DefaultLanguage is the fallback bundle for missing keys and the default
// when no preference is on disk.
const DefaultLanguage LanguageCode = "en"

var ErrUnsupportedLanguage = errors.New("unsupported language")

// Language describes one shipped UI locale. DisplayName is in the locale's
// own script (a Hungarian entry reads "Magyar" regardless of UI language).
type Language struct {
	Code        LanguageCode `json:"code"`
	DisplayName string       `json:"displayName"`
	EnglishName string       `json:"englishName"`
}

type localeIndex struct {
	Languages []Language `json:"languages"`
}

// Bundle holds the parsed translation bundles. Loaded once at construction
// and never mutated.
type Bundle struct {
	mu        sync.RWMutex
	languages []Language
	bundles   map[LanguageCode]map[string]string
}

// NewBundle parses _index.json plus every <code>/common.json in the locale
// tree. Hard-fails only when the default language is missing; other locales
// without a bundle are dropped with a warning.
func NewBundle(localesFS fs.FS) (*Bundle, error) {
	idx, err := loadLocaleIndex(localesFS)
	if err != nil {
		return nil, fmt.Errorf("load locale index: %w", err)
	}

	bundles := make(map[LanguageCode]map[string]string, len(idx.Languages))
	available := make([]Language, 0, len(idx.Languages))
	for _, l := range idx.Languages {
		b, err := loadBundle(localesFS, l.Code)
		if err != nil {
			log.Warnf("skip language %q: %v", l.Code, err)
			continue
		}
		bundles[l.Code] = b
		available = append(available, l)
	}

	if _, ok := bundles[DefaultLanguage]; !ok {
		return nil, fmt.Errorf("default language %q bundle missing", DefaultLanguage)
	}

	sort.Slice(available, func(i, j int) bool { return available[i].Code < available[j].Code })

	return &Bundle{
		languages: available,
		bundles:   bundles,
	}, nil
}

// Languages returns a copy of the available locales.
func (b *Bundle) Languages() []Language {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Language, len(b.languages))
	copy(out, b.languages)
	return out
}

func (b *Bundle) HasLanguage(code LanguageCode) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.bundles[code]
	return ok
}

// BundleFor returns a copy of the full key->text map for one language.
func (b *Bundle) BundleFor(code LanguageCode) (map[string]string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bundle, ok := b.bundles[code]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedLanguage, code)
	}
	out := make(map[string]string, len(bundle))
	for k, v := range bundle {
		out[k] = v
	}
	return out, nil
}

// Translate resolves key for lang, substituting args given as name/value
// pairs ("version", "1.2.3" replaces "{version}"). Unknown keys fall back to
// the default language, then to the key itself so a miss is visible in the UI.
func (b *Bundle) Translate(lang LanguageCode, key string, args ...string) string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if v, ok := b.bundles[lang][key]; ok {
		return applyPlaceholders(v, args)
	}
	if lang != DefaultLanguage {
		if v, ok := b.bundles[DefaultLanguage][key]; ok {
			return applyPlaceholders(v, args)
		}
	}
	return key
}

// applyPlaceholders substitutes {name} in s using args as flat name/value
// pairs. An odd-length args drops the trailing item.
func applyPlaceholders(s string, args []string) string {
	if len(args) == 0 {
		return s
	}
	if len(args)%2 != 0 {
		log.Debugf("i18n placeholder args not paired: %d items, last dropped", len(args))
		args = args[:len(args)-1]
	}
	for j := 0; j < len(args); j += 2 {
		s = strings.ReplaceAll(s, "{"+args[j]+"}", args[j+1])
	}
	return s
}

func loadLocaleIndex(localesFS fs.FS) (*localeIndex, error) {
	data, err := fs.ReadFile(localesFS, localeIndexFile)
	if err != nil {
		return nil, err
	}
	var idx localeIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("parse %s: %w", localeIndexFile, err)
	}
	if len(idx.Languages) == 0 {
		return nil, errors.New("no languages declared")
	}
	return &idx, nil
}

// bundleEntry is one translation key on disk; Description is Crowdin context,
// ignored at runtime.
type bundleEntry struct {
	Message     string `json:"message"`
	Description string `json:"description,omitempty"`
}

func loadBundle(localesFS fs.FS, code LanguageCode) (map[string]string, error) {
	p := path.Join(string(code), commonBundleFile)
	data, err := fs.ReadFile(localesFS, p)
	if err != nil {
		return nil, err
	}
	var entries map[string]bundleEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	bundle := make(map[string]string, len(entries))
	for k, e := range entries {
		bundle[k] = e.Message
	}
	return bundle, nil
}
