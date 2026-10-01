package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/bodytap"
)

// ErrUnsafeRequestPath indicates that a request path cannot be matched safely.
var ErrUnsafeRequestPath = errors.New("unsafe request path")

// TargetResolver is an immutable routing snapshot shared by auth and forwarding.
type TargetResolver struct {
	mapping     Mapping
	strictPaths bool
	hasBypass   bool
}

type targetResolution struct {
	result  targetResult
	matched bool
}

type targetResolutionContextKey struct{}

// NewTargetResolver builds an immutable target-routing snapshot.
func NewTargetResolver(mapping Mapping) (*TargetResolver, error) {
	snapshot, err := cloneResolverMapping(mapping)
	if err != nil {
		return nil, err
	}

	resolver := &TargetResolver{mapping: snapshot}
	for _, target := range snapshot.Paths {
		action := effectiveAccessAction(target.AccessAction)
		if action != AccessActionInherit {
			resolver.strictPaths = true
		}
		if action == AccessActionBypass {
			resolver.hasBypass = true
		}
	}
	return resolver, nil
}

// ResolveRequest selects and pins a target for both auth and forwarding.
func (r *TargetResolver) ResolveRequest(req *http.Request) (*http.Request, AccessAction, error) {
	if r == nil {
		return req, AccessActionInherit, nil
	}
	if req == nil || req.URL == nil {
		return req, AccessActionInherit, fmt.Errorf("%w: missing URL", ErrUnsafeRequestPath)
	}
	if r.strictPaths {
		if err := validateAccessPath(req.URL); err != nil {
			return req, AccessActionInherit, err
		}
	}

	result, matched := findTargetInMapping(req.URL.Path, r.mapping)
	resolution := targetResolution{result: result, matched: matched}
	ctx := context.WithValue(req.Context(), targetResolutionContextKey{}, resolution)
	resolvedReq := req.WithContext(ctx)
	if !matched {
		return resolvedReq, AccessActionInherit, nil
	}

	if cd := CapturedDataFromContext(ctx); cd != nil {
		cd.SetServiceID(result.serviceID)
		cd.SetAccountID(result.accountID)
		cd.SetAgentNetwork(result.target.AgentNetwork)
		cd.SetSuppressAccessLog(result.target.DisableAccessLog)
	}
	return resolvedReq, effectiveAccessAction(result.target.AccessAction), nil
}

// HasBypass reports whether the snapshot contains an authentication bypass.
func (r *TargetResolver) HasBypass() bool {
	return r != nil && r.hasBypass
}

func targetResolutionFromContext(ctx context.Context) (targetResolution, bool) {
	resolution, ok := ctx.Value(targetResolutionContextKey{}).(targetResolution)
	return resolution, ok
}

func effectiveAccessAction(action AccessAction) AccessAction {
	if action == "" {
		return AccessActionInherit
	}
	return action
}

func mappingHasNonDefaultAccessAction(mapping Mapping) bool {
	for _, target := range mapping.Paths {
		if target != nil && effectiveAccessAction(target.AccessAction) != AccessActionInherit {
			return true
		}
	}
	return false
}

func cloneResolverMapping(mapping Mapping) (Mapping, error) {
	snapshot := mapping
	snapshot.Paths = make(map[string]*PathTarget, len(mapping.Paths))
	snapshot.StripAuthHeaders = append([]string(nil), mapping.StripAuthHeaders...)
	snapshot.sortedPaths = make([]string, 0, len(mapping.Paths))

	for path, target := range mapping.Paths {
		if target == nil || target.URL == nil {
			return Mapping{}, fmt.Errorf("target for path %q is incomplete", path)
		}
		action := effectiveAccessAction(target.AccessAction)
		switch action {
		case AccessActionInherit, AccessActionBypass, AccessActionBlock:
		default:
			return Mapping{}, fmt.Errorf("unknown access action %q for path %q", target.AccessAction, path)
		}
		if action == AccessActionBypass && target.AgentNetwork {
			return Mapping{}, fmt.Errorf("authentication bypass is not allowed for Agent Network target %q", path)
		}
		if action != AccessActionInherit {
			if err := validateAccessPrefix(path); err != nil {
				return Mapping{}, fmt.Errorf("invalid access-controlled path %q: %w", path, err)
			}
		}

		cloned := clonePathTarget(target)
		cloned.AccessAction = action
		snapshot.Paths[path] = cloned
		snapshot.sortedPaths = append(snapshot.sortedPaths, path)
	}
	sort.Slice(snapshot.sortedPaths, func(i, j int) bool {
		return len(snapshot.sortedPaths[i]) > len(snapshot.sortedPaths[j])
	})
	snapshot.requirePinnedResolution = mappingHasNonDefaultAccessAction(snapshot)
	return snapshot, nil
}

func validateAccessPrefix(prefix string) error {
	if strings.ContainsAny(prefix, "?#") {
		return fmt.Errorf("%w: query or fragment delimiter", ErrUnsafeRequestPath)
	}
	return validateAccessPath(&url.URL{Path: prefix})
}

func clonePathTarget(target *PathTarget) *PathTarget {
	cloned := *target
	clonedURL := *target.URL
	cloned.URL = &clonedURL
	cloned.CustomHeaders = cloneStringMap(target.CustomHeaders)
	cloned.Middlewares = cloneMiddlewareSpecs(target.Middlewares)
	cloned.CaptureConfig = cloneCaptureConfig(target.CaptureConfig)
	return &cloned
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneMiddlewareSpecs(specs []middleware.Spec) []middleware.Spec {
	if specs == nil {
		return nil
	}
	cloned := make([]middleware.Spec, len(specs))
	for i, spec := range specs {
		cloned[i] = spec.Clone()
	}
	return cloned
}

func cloneCaptureConfig(config *bodytap.Config) *bodytap.Config {
	if config == nil {
		return nil
	}
	cloned := *config
	cloned.ContentTypes = append([]string(nil), config.ContentTypes...)
	return &cloned
}

func findTargetInMapping(path string, mapping Mapping) (targetResult, bool) {
	for _, prefix := range mapping.sortedPaths {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		target := mapping.Paths[prefix]
		if target == nil || target.URL == nil {
			continue
		}
		return targetResult{
			target:           target,
			matchedPath:      prefix,
			serviceID:        mapping.ID,
			accountID:        mapping.AccountID,
			passHostHeader:   mapping.PassHostHeader,
			rewriteRedirects: mapping.RewriteRedirects,
			stripAuthHeaders: mapping.StripAuthHeaders,
			requirePinned:    mapping.requirePinnedResolution,
		}, true
	}
	return targetResult{requirePinned: mapping.requirePinnedResolution}, false
}

func validateAccessPath(requestURL *url.URL) error {
	if requestURL.Opaque != "" || requestURL.Path == "" || requestURL.Path[0] != '/' {
		return fmt.Errorf("%w: path must be absolute", ErrUnsafeRequestPath)
	}
	if !utf8.ValidString(requestURL.Path) {
		return fmt.Errorf("%w: path is not valid UTF-8", ErrUnsafeRequestPath)
	}
	if requestURL.RawPath != "" {
		decoded, err := url.PathUnescape(requestURL.RawPath)
		if err != nil || decoded != requestURL.Path {
			return fmt.Errorf("%w: invalid escaped path", ErrUnsafeRequestPath)
		}
	}
	if strings.Contains(requestURL.Path, "//") || strings.ContainsAny(requestURL.Path, "\\;?#") {
		return fmt.Errorf("%w: ambiguous path separator", ErrUnsafeRequestPath)
	}
	for _, segment := range strings.Split(requestURL.Path, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("%w: dot segment", ErrUnsafeRequestPath)
		}
	}
	for _, char := range requestURL.Path {
		if char < 0x20 || char == 0x7f {
			return fmt.Errorf("%w: control character", ErrUnsafeRequestPath)
		}
	}

	escapedPath := requestURL.EscapedPath()
	for i := 0; i < len(escapedPath); i++ {
		if escapedPath[i] != '%' {
			continue
		}
		if i+2 >= len(escapedPath) {
			return fmt.Errorf("%w: truncated escape", ErrUnsafeRequestPath)
		}
		value, ok := decodeHexByte(escapedPath[i+1], escapedPath[i+2])
		if !ok {
			return fmt.Errorf("%w: invalid escape", ErrUnsafeRequestPath)
		}
		switch value {
		case '/', '\\', '.', '%', 0:
			return fmt.Errorf("%w: ambiguous escaped character", ErrUnsafeRequestPath)
		}
		if value < 0x20 || value == 0x7f {
			return fmt.Errorf("%w: escaped control character", ErrUnsafeRequestPath)
		}
		i += 2
	}
	return nil
}

func decodeHexByte(high, low byte) (byte, bool) {
	hi, ok := hexNibble(high)
	if !ok {
		return 0, false
	}
	lo, ok := hexNibble(low)
	if !ok {
		return 0, false
	}
	return hi<<4 | lo, true
}

func hexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}
