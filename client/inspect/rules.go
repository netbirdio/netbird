package inspect

import (
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/acl/id"
	"github.com/netbirdio/netbird/shared/management/domain"
)

// RuleEngine evaluates proxy rules against connection metadata.
// It is safe for concurrent use.
type RuleEngine struct {
	mu    sync.RWMutex
	rules []Rule
	// defaultAction applies when no rule matches.
	defaultAction Action
	log           *log.Entry
}

// NewRuleEngine creates a rule engine with the given default action.
func NewRuleEngine(logger *log.Entry, defaultAction Action) *RuleEngine {
	return &RuleEngine{
		defaultAction: defaultAction,
		log:           logger,
	}
}

// UpdateRules replaces the rule set and default action. Rules are sorted by priority.
func (e *RuleEngine) UpdateRules(rules []Rule, defaultAction Action) {
	sorted := make([]Rule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	e.mu.Lock()
	e.rules = sorted
	e.defaultAction = defaultAction
	e.mu.Unlock()
}

// EvalResult holds the outcome of a rule evaluation.
type EvalResult struct {
	Action Action
	RuleID id.RuleID
}

// Evaluate determines the action for a connection based on the rule set.
// Pass empty path for connection-level evaluation (TLS/SNI), non-empty for request-level (HTTP).
func (e *RuleEngine) Evaluate(src netip.Addr, dstDomain domain.Domain, dstAddr netip.Addr, dstPort uint16, proto ProtoType, path string) Action {
	r := e.EvaluateWithResult(src, dstDomain, dstAddr, dstPort, proto, path)
	return r.Action
}

// EvaluateWithResult is like Evaluate but also returns the matched rule ID.
func (e *RuleEngine) EvaluateWithResult(src netip.Addr, dstDomain domain.Domain, dstAddr netip.Addr, dstPort uint16, proto ProtoType, path string) EvalResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for i := range e.rules {
		rule := &e.rules[i]
		if e.ruleMatches(rule, src, dstDomain, dstAddr, dstPort, proto, path) {
			e.log.Tracef("rule %s matched: action=%s src=%s domain=%s dst=%s:%d proto=%s path=%s",
				rule.ID, rule.Action, src, dstDomain.SafeString(), dstAddr, dstPort, proto, path)
			return EvalResult{Action: rule.Action, RuleID: rule.ID}
		}
	}

	e.log.Tracef("no rule matched, default=%s: src=%s domain=%s dst=%s:%d proto=%s path=%s",
		e.defaultAction, src, dstDomain.SafeString(), dstAddr, dstPort, proto, path)
	return EvalResult{Action: e.defaultAction}
}

// HasPathRulesForDomain returns true if any rule matching the domain has non-empty Paths.
// Used to force MITM inspection when path-level rules exist (paths are only visible after decryption).
func (e *RuleEngine) HasPathRulesForDomain(dstDomain domain.Domain) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for i := range e.rules {
		if len(e.rules[i].Paths) > 0 && e.matchDomain(&e.rules[i], dstDomain) {
			return true
		}
	}
	return false
}

// ruleMatches checks whether all non-empty fields of a rule match.
// Empty fields are treated as "match any".
// All specified fields must match (AND logic).
func (e *RuleEngine) ruleMatches(rule *Rule, src netip.Addr, dstDomain domain.Domain, dstAddr netip.Addr, dstPort uint16, proto ProtoType, path string) bool {
	if !e.matchSource(rule, src) {
		return false
	}

	if !e.matchDomain(rule, dstDomain) {
		return false
	}

	if !e.matchNetwork(rule, dstAddr) {
		return false
	}

	if !e.matchPort(rule, dstPort) {
		return false
	}

	if !e.matchProtocol(rule, proto) {
		return false
	}

	if !e.matchPaths(rule, path) {
		return false
	}

	return true
}

// matchSource returns true if src matches any of the rule's source CIDRs,
// or if no source CIDRs are specified (match any).
func (e *RuleEngine) matchSource(rule *Rule, src netip.Addr) bool {
	if len(rule.Sources) == 0 {
		return true
	}

	for _, prefix := range rule.Sources {
		if prefix.Contains(src) {
			return true
		}
	}

	return false
}

// matchDomain returns true if dstDomain matches any of the rule's domain patterns,
// or if no domain patterns are specified (match any).
func (e *RuleEngine) matchDomain(rule *Rule, dstDomain domain.Domain) bool {
	if len(rule.Domains) == 0 {
		return true
	}

	// If we have domain rules but no domain to match against (e.g., raw IP connection),
	// the domain condition does not match.
	if dstDomain == "" {
		return false
	}

	for _, pattern := range rule.Domains {
		if MatchDomain(pattern, dstDomain) {
			return true
		}
	}

	return false
}

// matchNetwork returns true if dstAddr is within any of the rule's destination CIDRs,
// or if no destination CIDRs are specified (match any).
func (e *RuleEngine) matchNetwork(rule *Rule, dstAddr netip.Addr) bool {
	if len(rule.Networks) == 0 {
		return true
	}

	for _, prefix := range rule.Networks {
		if prefix.Contains(dstAddr) {
			return true
		}
	}

	return false
}

// matchProtocol returns true if proto matches any of the rule's protocols,
// or if no protocols are specified (match any).
func (e *RuleEngine) matchProtocol(rule *Rule, proto ProtoType) bool {
	if len(rule.Protocols) == 0 {
		return true
	}

	for _, p := range rule.Protocols {
		if p == proto {
			return true
		}
	}

	return false
}

// matchPort returns true if dstPort matches any of the rule's destination ports,
// or if no ports are specified (match any).
func (e *RuleEngine) matchPort(rule *Rule, dstPort uint16) bool {
	if len(rule.Ports) == 0 {
		return true
	}

	return slices.Contains(rule.Ports, dstPort)
}

// matchPaths returns true if path matches any of the rule's path patterns,
// or if no paths are specified (match any). Empty path (connection-level eval) matches all.
func (e *RuleEngine) matchPaths(rule *Rule, path string) bool {
	if len(rule.Paths) == 0 {
		return true
	}
	// Connection-level (path=""): rules with paths don't match at connection level.
	// HasPathRulesForDomain forces the connection to inspect, so paths are
	// checked per-request once the HTTP request is visible.
	if path == "" {
		return false
	}
	for _, pattern := range rule.Paths {
		if matchPath(pattern, path) {
			return true
		}
	}
	return false
}

// matchPath checks if a URL path matches a pattern.
// Supports: exact ("/login"), prefix with wildcard ("/api/*"),
// and contains ("*/admin/*"). A bare "*" matches everything.
func matchPath(pattern, path string) bool {
	if pattern == "*" {
		return true
	}

	hasLeadingStar := strings.HasPrefix(pattern, "*")
	hasTrailingStar := strings.HasSuffix(pattern, "*")

	switch {
	case hasLeadingStar && hasTrailingStar:
		// */admin/* = contains
		middle := strings.Trim(pattern, "*")
		return strings.Contains(path, middle)
	case hasTrailingStar:
		// /api/* = prefix
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	case hasLeadingStar:
		// *.json = suffix
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(path, suffix)
	default:
		// exact
		return path == pattern
	}
}
