//go:build linux || darwin

package ssh

import (
	log "github.com/sirupsen/logrus"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

func loadUser(cmd *exec.Cmd, localUser *user.User) error {
	uid, err := strconv.Atoi(localUser.Uid)
	if err != nil {
		log.Debugf("failed converting local uid to int %s", localUser.Uid)
		return err
	}
	gid, err := strconv.Atoi(localUser.Gid)
	if err != nil {
		log.Debugf("failed converting local gid to int %s", localUser.Gid)
		return err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	return nil
}
