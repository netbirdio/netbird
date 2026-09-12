package filedrop

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
)

// maxDeliveredNameBytes bounds a delivered filename. Common filesystems stop at
// 255 bytes per entry, and the room left over takes the " (N)" a name collision
// appends without pushing the result back over the limit.
const maxDeliveredNameBytes = 240

func deliver(spool *Spool, offer Offer, destDir string) ([]string, error) {
	files := false
	for _, f := range offer.Files {
		if f.Kind != KindText {
			files = true
			break
		}
	}

	if !files {
		spool.removeLocked(offer.ID)
		return nil, nil
	}

	if destDir == "" {
		return nil, fmt.Errorf("no destination directory configured")
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, fmt.Errorf("create destination dir: %w", err)
	}

	// Every item is attempted, and the ones that landed are reported alongside
	// the failure: stopping at the first error left earlier files sitting in the
	// destination while the caller was told the whole delivery had failed, with
	// no path recorded for them.
	var delivered []string
	var failed []string
	for i, f := range offer.Files {
		if f.Kind == KindText {
			continue
		}

		dest, err := moveToUniqueName(spool.Path(offer.ID, i), destDir, sanitizeFileName(f.Name, i))
		if err != nil {
			log.Warnf("failed to deliver %s of offer %s: %v", f.Name, offer.ID, err)
			failed = append(failed, f.Name)
			continue
		}
		if err := chownToDirOwner(dest, destDir); err != nil {
			log.Debugf("failed to adopt owner for %s: %v", dest, err)
		}
		delivered = append(delivered, dest)
	}

	spool.removeLocked(offer.ID)

	if len(failed) > 0 {
		return delivered, fmt.Errorf("deliver %s", strings.Join(failed, ", "))
	}
	return delivered, nil
}

func sanitizeFileName(name string, index int) string {
	name = stripNameControls(name)
	name = filepath.Base(filepath.Clean(strings.ReplaceAll(name, "\\", "/")))
	if name == "" || name == "." || name == ".." || name == string(filepath.Separator) {
		return fmt.Sprintf("file-%d", index)
	}
	return truncateNameBytes(name, maxDeliveredNameBytes)
}

// stripNameControls drops the characters that change how the rest of the name
// renders rather than what it addresses. A name ending in "gpj.exe" preceded by
// U+202E displays in a file manager as though it ended in ".jpg", and the C0
// controls have no business in a filename either.
func stripNameControls(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r < 0x20, r == 0x7f:
			return -1
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			return -1
		case r == 0x200e, r == 0x200f, r == 0x061c:
			return -1
		default:
			return r
		}
	}, name)
}

// truncateNameBytes keeps a name within one filesystem entry, preserving the
// extension so the delivered file still opens with the right application. A
// name over the limit is refused by the OS outright, which used to fail the
// whole delivery.
func truncateNameBytes(name string, limit int) string {
	if len(name) <= limit {
		return name
	}

	ext := filepath.Ext(name)
	if len(ext) > limit/2 {
		ext = ""
	}
	stem := name[:len(name)-len(ext)]

	room := limit - len(ext)
	for len(stem) > room {
		_, size := utf8.DecodeLastRuneInString(stem)
		stem = stem[:len(stem)-size]
	}
	return stem + ext
}

func moveToUniqueName(src, dir, name string) (string, error) {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)

	for attempt := 0; attempt < 1000; attempt++ {
		candidate := name
		if attempt > 0 {
			candidate = fmt.Sprintf("%s (%d)%s", stem, attempt, ext)
		}
		dest := filepath.Join(dir, candidate)

		f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			if os.IsExist(err) {
				continue
			}
			return "", fmt.Errorf("create destination: %w", err)
		}

		if err := moveInto(f, src); err != nil {
			_ = f.Close()
			_ = os.Remove(dest)
			return "", err
		}
		if err := f.Close(); err != nil {
			return "", fmt.Errorf("close destination: %w", err)
		}
		if err := os.Remove(src); err != nil {
			log.Debugf("failed to remove spooled source %s: %v", src, err)
		}
		return dest, nil
	}

	return "", fmt.Errorf("no free name for %s in %s", name, dir)
}

func moveInto(dst *os.File, src string) error {
	s, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open spooled file: %w", err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			log.Debugf("close spooled file: %v", err)
		}
	}()

	if _, err := io.Copy(dst, s); err != nil {
		return fmt.Errorf("copy payload: %w", err)
	}
	return nil
}
