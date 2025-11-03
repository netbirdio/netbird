//go:build !windows

package installer

func (c *Installer) LogFiles() []string {
	return []string{}
}

func (u *Installer) CleanUpInstallerFiles() error {
	return nil
}
