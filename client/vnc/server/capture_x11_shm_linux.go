//go:build linux && !android

package server

import (
	"fmt"
	"image"

	"github.com/jezek/xgb/shm"
	"github.com/jezek/xgb/xproto"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func (c *X11Capturer) initSHM() error {
	if err := shm.Init(c.conn); err != nil {
		return fmt.Errorf("init SHM extension: %w", err)
	}

	size := c.w * c.h * 4
	id, err := unix.SysvShmGet(unix.IPC_PRIVATE, size, unix.IPC_CREAT|0600)
	if err != nil {
		return fmt.Errorf("shmget: %w", err)
	}

	addr, err := unix.SysvShmAttach(id, 0, 0)
	if err != nil {
		if _, ctlErr := unix.SysvShmCtl(id, unix.IPC_RMID, nil); ctlErr != nil {
			log.Debugf("shmctl IPC_RMID on attach failure: %v", ctlErr)
		}
		return fmt.Errorf("shmat: %w", err)
	}

	seg, err := shm.NewSegId(c.conn)
	if err != nil {
		releaseShmSegment(id, addr)
		return fmt.Errorf("new SHM seg: %w", err)
	}

	// The X server attaches before the segment is marked for deletion: since
	// Linux 3.10 a shmat() against an IPC_RMID'd segment fails with EIDRM, so
	// marking it first would push us onto the slow non-SHM path.
	if err := shm.AttachChecked(c.conn, seg, uint32(id), false).Check(); err != nil {
		releaseShmSegment(id, addr)
		return fmt.Errorf("SHM attach to X: %w", err)
	}

	// Both ends hold the segment at this point, so marking it for deletion
	// frees it as soon as the last of them detaches, even if this process
	// dies without cleaning up.
	if _, err := unix.SysvShmCtl(id, unix.IPC_RMID, nil); err != nil {
		log.Debugf("shmctl IPC_RMID: %v", err)
	}

	c.shmID = id
	c.shmAddr = addr
	c.shmSeg = uint32(seg)
	c.useSHM = true
	return nil
}

// releaseShmSegment gives a segment back on a setup path that failed after
// attaching it: detach this process, then mark it for deletion so it does not
// linger in the kernel's IPC table for the life of the host.
func releaseShmSegment(id int, addr []byte) {
	if err := unix.SysvShmDetach(addr); err != nil {
		log.Debugf("shmdt on setup failure: %v", err)
	}
	if _, err := unix.SysvShmCtl(id, unix.IPC_RMID, nil); err != nil {
		log.Debugf("shmctl IPC_RMID on setup failure: %v", err)
	}
}

func (c *X11Capturer) captureSHM() (*image.RGBA, error) {
	if err := c.fillSHM(); err != nil {
		return nil, err
	}
	img := c.nextBuffer()
	swizzleBGRAtoRGBA(img.Pix, c.shmAddr[:c.w*c.h*4])
	return img, nil
}

// captureSHMInto runs a single SHM GetImage and swizzles directly into the
// caller-provided destination, skipping the internal double-buffer.
func (c *X11Capturer) captureSHMInto(dst *image.RGBA) error {
	if err := c.fillSHM(); err != nil {
		return err
	}
	swizzleBGRAtoRGBA(dst.Pix, c.shmAddr[:c.w*c.h*4])
	return nil
}

func (c *X11Capturer) fillSHM() error {
	cookie := shm.GetImage(c.conn, xproto.Drawable(c.screen.Root),
		0, 0, uint16(c.w), uint16(c.h), 0xFFFFFFFF,
		xproto.ImageFormatZPixmap, shm.Seg(c.shmSeg), 0)
	if _, err := cookie.Reply(); err != nil {
		return fmt.Errorf("SHM GetImage: %w", err)
	}
	return nil
}

func (c *X11Capturer) closeSHM() {
	if c.useSHM {
		shm.Detach(c.conn, shm.Seg(c.shmSeg))
		if err := unix.SysvShmDetach(c.shmAddr); err != nil {
			log.Debugf("shmdt on close: %v", err)
		}
	}
}
