package ssh

import (
	"fmt"
	"os/user"
	"syscall"
)

func getSysProcAttr(localUser *user.User) (*syscall.SysProcAttr, error) {
	return nil, fmt.Errorf("unsupported operation on windows")
}
