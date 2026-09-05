package filedrop

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

func deliver(spool *Spool, offer Offer, destDir string) ([]string, error) {
	files := false
	for _, f := range offer.Files {
		if f.Kind != KindText {
			files = true
			break
		}
	}

	if !files {
		spool.Remove(offer.ID)
		return nil, nil
	}

	if destDir == "" {
		return nil, fmt.Errorf("no destination directory configured")
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, fmt.Errorf("create destination dir: %w", err)
	}

	var delivered []string
	for i, f := range offer.Files {
		if f.Kind == KindText {
			continue
		}

		dest, err := moveToUniqueName(spool.Path(offer.ID, i), destDir, sanitizeFileName(f.Name, i))
		if err != nil {
			return delivered, fmt.Errorf("deliver %s: %w", f.Name, err)
		}
		if err := chownToDirOwner(dest, destDir); err != nil {
			log.Debugf("failed to adopt owner for %s: %v", dest, err)
		}
		delivered = append(delivered, dest)
	}

	spool.Remove(offer.ID)
	return delivered, nil
}

func sanitizeFileName(name string, index int) string {
	name = filepath.Base(filepath.Clean(strings.ReplaceAll(name, "\\", "/")))
	if name == "" || name == "." || name == ".." || name == string(filepath.Separator) {
		return fmt.Sprintf("file-%d", index)
	}
	return name
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
