package installer

import (
	"context"
	"os/exec"
)

const (
	TypeHomebrew Type = "Homebrew"
	TypePKG      Type = "pkg"
)

type Type string

func TypeOfInstaller(ctx context.Context) Type {
	cmd := exec.CommandContext(ctx, "pkgutil", "--pkg-info", "io.netbird.client")
	_, err := cmd.Output()
	if err != nil && cmd.ProcessState.ExitCode() == 1 {
		// Not installed using pkg file, thus installed using Homebrew

		return TypeHomebrew
	}
	return TypePKG
}
