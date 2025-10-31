//go:build !windows

package installer

func (c *Installer) LogFiles() []string {
	return []string{}
}

func (u *Installer) CleanUpInstallerFile() error {
	return nil
}
