package mdm

import "net/url"

// PreSharedKeyRedactedSentinel is the redaction mask returned in place of a
// real pre-shared key; an incoming value equal to it is a round-trip echo,
// never an override.
const PreSharedKeyRedactedSentinel = "**********"

// ConflictCheck is a value-aware comparison between a single requested field
// and the corresponding MDM-enforced value.
type ConflictCheck struct {
	Key   string
	Check func(*Policy) bool
}

// ConflictBool builds a ConflictCheck for a boolean MDM key.
func ConflictBool(key string, p *bool) ConflictCheck {
	return ConflictCheck{
		Key: key,
		Check: func(pol *Policy) bool {
			if p == nil {
				return true
			}
			want, ok := pol.GetBool(key)
			return ok && want == *p
		},
	}
}

// ConflictStringPtr builds a ConflictCheck for an optional string MDM key,
// where an explicit empty value is still a request to change the setting. A
// nil p means "field not set" (no override requested).
func ConflictStringPtr(key string, p *string) ConflictCheck {
	return ConflictCheck{
		Key: key,
		Check: func(pol *Policy) bool {
			if p == nil {
				return true
			}
			want, ok := pol.GetString(key)
			return ok && want == *p
		},
	}
}

// ConflictURL builds a ConflictCheck for a URL-typed MDM key; both sides are
// normalized via CanonicalURL before comparison.
func ConflictURL(key, got string) ConflictCheck {
	return ConflictCheck{
		Key: key,
		Check: func(pol *Policy) bool {
			if got == "" {
				return true
			}
			want, ok := pol.GetString(key)
			return ok && CanonicalURL(want) == CanonicalURL(got)
		},
	}
}

// ConflictInt64 builds a ConflictCheck for an integer MDM key.
func ConflictInt64(key string, p *int64) ConflictCheck {
	return ConflictCheck{
		Key: key,
		Check: func(pol *Policy) bool {
			if p == nil {
				return true
			}
			want, ok := pol.GetInt(key)
			return ok && want == *p
		},
	}
}

// ResolveConflicts returns the names of keys whose requested value diverges
// from the policy-enforced value; keys the policy does not manage are skipped.
func ResolveConflicts(policy *Policy, checks []ConflictCheck) []string {
	if policy.IsEmpty() {
		return nil
	}
	var conflicts []string
	for _, c := range checks {
		if !policy.HasKey(c.Key) {
			continue
		}
		if !c.Check(policy) {
			conflicts = append(conflicts, c.Key)
		}
	}
	return conflicts
}

// CanonicalURL normalizes a service URL by appending the scheme default port
// when none is present; unparseable input is returned unchanged.
func CanonicalURL(s string) string {
	u, err := url.ParseRequestURI(s)
	if err != nil {
		return s
	}
	if u.Port() == "" {
		switch u.Scheme {
		case "https":
			u.Host += ":443"
		case "http":
			u.Host += ":80"
		}
	}
	return u.String()
}
