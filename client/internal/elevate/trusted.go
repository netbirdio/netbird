package elevate

import (
	"fmt"
	"os"
	"path/filepath"
)

// trustedSelf returns the path of this executable, provided it is one we are
// willing to have run as root.
//
// The check is what keeps elevation from becoming a way to launder someone
// else's code into a root process: the user consents to NetBird being elevated,
// having been shown NetBird's name, so what runs must be the file NetBird was
// installed as and not something a third party could have swapped for it. An
// executable only its owner can write is that; anything wider is refused, and
// the caller falls back to showing the command instead.
//
// The owner writing to their own executable is not part of that threat: code
// running as the user can already prompt them for anything, and could just as
// well ask them to run the command by hand. What matters is that no *other*
// unprivileged account can reach it.
func trustedSelf() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate this executable: %w", err)
	}

	// Resolve symlinks so the checks below apply to the file that would actually
	// be executed, not to a link somebody else may control.
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", exe, err)
	}

	if err := checkOnlyOwnerWritable(resolved); err != nil {
		return "", fmt.Errorf("%w: %s cannot be trusted to run as root: %w", ErrUnavailable, resolved, err)
	}
	return resolved, nil
}
