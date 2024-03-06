package bypass

import (
	"fmt"
	"net/http"
	"path"
	"sync"

	log "github.com/sirupsen/logrus"
)

var byPassMutex sync.RWMutex

// bypassPaths is a set of paths that should bypass middleware.
var bypassPaths = make(map[string]struct{})

// AddBypassPath adds an exact path to the list of paths that bypass middleware.
// Paths can include wildcards, such as /api/*. Paths are matched using path.Match.
// Returns an error if the path has invalid pattern.
func AddBypassPath(path string) error {
	byPassMutex.Lock()
	defer byPassMutex.Unlock()
	if err := validatePath(path); err != nil {
		return fmt.Errorf("validate: %w", err)
	}
	bypassPaths[path] = struct{}{}
	return nil
}

// RemovePath removes a path from the list of paths that bypass middleware.
func RemovePath(path string) {
	byPassMutex.Lock()
	defer byPassMutex.Unlock()
	delete(bypassPaths, path)
}

// GetList returns a list of all bypass paths.
func GetList() []string {
	byPassMutex.RLock()
	defer byPassMutex.RUnlock()

	list := make([]string, 0, len(bypassPaths))
	for k := range bypassPaths {
		list = append(list, k)
	}

	return list
}

// ShouldBypass checks if the request path is one of the auth bypass paths and returns true if the middleware should be bypassed.
// This can be used to bypass authz/authn middlewares for certain paths, such as webhooks that implement their own authentication.
func ShouldBypass(requestPath string, h http.Handler, w http.ResponseWriter, r *http.Request) bool {
	byPassMutex.RLock()
	defer byPassMutex.RUnlock()

	for bypassPath := range bypassPaths {
		matched, err := path.Match(bypassPath, requestPath)
		if err != nil {
			log.Errorf("Error matching path %s with %s from %s: %v", bypassPath, requestPath, GetList(), err)
			continue
		}
		if matched {
			h.ServeHTTP(w, r)
			return true
		}
	}

	return false
}

func validatePath(p string) error {
	_, err := path.Match(p, "")
	return err
}
