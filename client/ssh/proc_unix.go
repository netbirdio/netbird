//go:build linux || darwin

package ssh

import (
	log "github.com/sirupsen/logrus"
	"os/user"
	"strconv"
	"syscall"
)

func getSysProcAttr(localUser *user.User) (*syscall.SysProcAttr, error) {
	uid, err := strconv.Atoi(localUser.Uid)
	if err != nil {
		log.Debugf("failed converting local uid to int %s", localUser.Uid)
		return nil, err
	}
	gid, err := strconv.Atoi(localUser.Gid)
	if err != nil {
		log.Debugf("failed converting local gid to int %s", localUser.Gid)
		return nil, err
	}
	attr := &syscall.SysProcAttr{}
	attr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	return attr, nil
}
