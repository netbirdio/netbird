package iptables

type ruleset struct {
	ips map[string]struct{}
}

func (s ruleset) addIP(ip string) {
	s.ips[ip] = struct{}{}
}

type rulesetStore struct {
	ruleSets map[string]ruleset // ipsetName -> ruleset
}

func newRulesetStore() *rulesetStore {
	return &rulesetStore{
		ruleSets: make(map[string]ruleset),
	}
}

func (s *rulesetStore) ruleset(ipsetName string) (ruleset, bool) {
	r, ok := s.ruleSets[ipsetName]
	return r, ok
}

func (s *rulesetStore) newRuleset(ip string) ruleset {
	ips := make(map[string]struct{})
	ips[ip] = struct{}{}

	return ruleset{
		ips: ips,
	}
}

func (s *rulesetStore) deleteRuleset(ipsetName string) {
	s.ruleSets[ipsetName] = ruleset{}
	delete(s.ruleSets, ipsetName)
}

func (s *rulesetStore) ipsetNames() []string {
	names := make([]string, 0, len(s.ruleSets))
	for name := range s.ruleSets {
		names = append(names, name)
	}
	return names
}
