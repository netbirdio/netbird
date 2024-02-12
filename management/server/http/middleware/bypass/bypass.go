package bypass

import (
	"net/http"
	"sync"
)

var byPassMutex sync.RWMutex

// bypassPaths is a set of paths that should bypass middleware.
var bypassPaths = make(map[string]struct{})

// AddBypassPath adds an exact path to the list of paths that bypass middleware.
func AddBypassPath(path string) {
	byPassMutex.Lock()
	defer byPassMutex.Unlock()
	bypassPaths[path] = struct{}{}
}

// RemovePath removes a path from the list of paths that bypass middleware.
func RemovePath(path string) {
	byPassMutex.Lock()
	defer byPassMutex.Unlock()
	delete(bypassPaths, path)
}

// ShouldBypass checks if the request path is one of the auth bypass paths and returns true if the middleware should be bypassed.
// This can be used to bypass authz/authn middlewares for certain paths, such as webhooks that implement their own authentication.
func ShouldBypass(requestPath string, h http.Handler, w http.ResponseWriter, r *http.Request) bool {
	byPassMutex.RLock()
	defer byPassMutex.RUnlock()

	if _, ok := bypassPaths[requestPath]; ok {
		h.ServeHTTP(w, r)
		return true
	}

	return false
}
