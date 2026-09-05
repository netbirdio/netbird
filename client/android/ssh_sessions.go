//go:build android

package android

const (
	sshSessionsNamespace = "ssh-sessions"
	maxStoredSSHSessions = 50
)

type sshSessionRecord struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	Port int    `json:"port"`
	User string `json:"user"`
}

type sshSessionsSection struct {
	Sessions []sshSessionRecord `json:"sessions"`
}

// SSHSessionEntry is one stored SSH session, without any credential.
type SSHSessionEntry struct {
	ID   string
	Host string
	Port int
	User string
}

// SSHSessionArray wraps stored SSH sessions for gomobile compatibility.
type SSHSessionArray struct {
	items []*SSHSessionEntry
}

// NewSSHSessionArray creates an empty session array to fill via Add.
func NewSSHSessionArray() *SSHSessionArray {
	return &SSHSessionArray{}
}

// Add appends a session entry, oldest first.
func (a *SSHSessionArray) Add(id, host string, port int, user string) {
	a.items = append(a.items, &SSHSessionEntry{ID: id, Host: host, Port: port, User: user})
}

// Length returns the number of entries.
func (a *SSHSessionArray) Length() int {
	return len(a.items)
}

// Get returns the entry at index i, or nil when out of range.
func (a *SSHSessionArray) Get(i int) *SSHSessionEntry {
	if i < 0 || i >= len(a.items) {
		return nil
	}
	return a.items[i]
}

// SSHSessionStore reads and writes a profile's stored SSH sessions.
type SSHSessionStore struct {
	prefs prefsStore
}

// NewSSHSessionStore opens the session store of the given profile.
func NewSSHSessionStore(configDir, profileID string) (*SSHSessionStore, error) {
	prefs, err := newProfilePrefs(configDir, profileID)
	if err != nil {
		return nil, err
	}
	return &SSHSessionStore{prefs: prefs}, nil
}

// Load returns the stored sessions, oldest first.
func (s *SSHSessionStore) Load() (*SSHSessionArray, error) {
	var section sshSessionsSection
	if _, err := s.prefs.Get(sshSessionsNamespace, &section); err != nil {
		return nil, err
	}

	out := NewSSHSessionArray()
	for _, record := range section.Sessions {
		if record.ID == "" || record.Host == "" {
			continue
		}
		out.Add(record.ID, record.Host, record.Port, record.User)
	}
	return out, nil
}

// Save replaces the stored sessions, keeping only the newest entries when the
// list exceeds the storage cap.
func (s *SSHSessionStore) Save(sessions *SSHSessionArray) error {
	var items []*SSHSessionEntry
	if sessions != nil {
		items = sessions.items
	}
	if len(items) > maxStoredSSHSessions {
		items = items[len(items)-maxStoredSSHSessions:]
	}

	records := make([]sshSessionRecord, 0, len(items))
	for _, item := range items {
		records = append(records, sshSessionRecord{ID: item.ID, Host: item.Host, Port: item.Port, User: item.User})
	}
	return s.prefs.Put(sshSessionsNamespace, sshSessionsSection{Sessions: records})
}
