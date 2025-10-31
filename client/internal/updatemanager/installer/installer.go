package installer

const (
	LogFile = "installer.log"
)

func (u *Installer) TempDir() string {
	return u.tempDir
}
