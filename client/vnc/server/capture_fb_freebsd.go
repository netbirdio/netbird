//go:build freebsd

package server

import (
	"fmt"
	"image"
	"sync"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// FreeBSD vt(4) framebuffer ioctl numbers from sys/fbio.h.
//
//	#define FBIOGTYPE _IOR('F', 0, struct fbtype)
//
// _IOR(g, n, t) on FreeBSD: dir=2 (read) <<30 | (sizeof(t) & 0x1fff)<<16
// | (g<<8) | n.  sizeof(struct fbtype)=24 → 0x40184600.
const fbioGType = 0x40184600

func defaultFBPath() string { return "/dev/ttyv0" }

// fbType mirrors FreeBSD's struct fbtype.
type fbType struct {
	FbType   int32
	FbHeight int32
	FbWidth  int32
	FbDepth  int32
	FbCMSize int32
	FbSize   int32
}

// FBCapturer reads pixels from FreeBSD's vt(4) framebuffer device. The
// vt(4) console exposes the active framebuffer via ttyv0 with FBIOGTYPE
// for geometry and mmap for backing memory. Pixel layout is assumed to
// be 32bpp BGRA (the common case for KMS-backed vt); fbtype doesn't
// expose channel offsets, so we don't try to handle exotic layouts here.
type FBCapturer struct {
	mu        sync.Mutex
	path      string
	fd        int
	mmap      []byte
	w, h      int
	bpp       int
	stride    int
	closeOnce sync.Once
}

// NewFBCapturer opens the given vt(4) device and queries its geometry.
func NewFBCapturer(path string) (*FBCapturer, error) {
	if path == "" {
		path = defaultFBPath()
	}
	fd, err := unix.Open(path, unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	var fbt fbType
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), fbioGType, uintptr(unsafe.Pointer(&fbt))); e != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("FBIOGTYPE: %v", e)
	}
	if fbt.FbDepth != 16 && fbt.FbDepth != 24 && fbt.FbDepth != 32 {
		unix.Close(fd)
		return nil, fmt.Errorf("unsupported framebuffer depth: %d", fbt.FbDepth)
	}
	if fbt.FbWidth <= 0 || fbt.FbHeight <= 0 || fbt.FbSize <= 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("invalid framebuffer geometry: %dx%d size=%d", fbt.FbWidth, fbt.FbHeight, fbt.FbSize)
	}

	mm, err := unix.Mmap(fd, 0, int(fbt.FbSize), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("mmap %s: %w (vt may not support mmap on this driver, e.g. virtio_gpu)", path, err)
	}

	bpp := int(fbt.FbDepth)
	stride := int(fbt.FbWidth) * (bpp / 8)
	c := &FBCapturer{
		path:   path,
		fd:     fd, // valid fd >= 0; we use -1 as the closed sentinel
		mmap:   mm,
		w:      int(fbt.FbWidth),
		h:      int(fbt.FbHeight),
		bpp:    bpp,
		stride: stride,
	}
	log.Infof("framebuffer capturer ready: %s %dx%d bpp=%d (freebsd vt)", path, c.w, c.h, c.bpp)
	return c, nil
}

// Width returns the framebuffer width.
func (c *FBCapturer) Width() int { return c.w }

// Height returns the framebuffer height.
func (c *FBCapturer) Height() int { return c.h }

// Capture allocates a fresh image and fills it with the current
// framebuffer contents.
func (c *FBCapturer) Capture() (*image.RGBA, error) {
	img := image.NewRGBA(image.Rect(0, 0, c.w, c.h))
	if err := c.CaptureInto(img); err != nil {
		return nil, err
	}
	return img, nil
}

// CaptureInto reads the framebuffer directly into dst.Pix. Assumes BGRA
// for 32bpp; the FreeBSD fbtype struct doesn't expose channel offsets.
func (c *FBCapturer) CaptureInto(dst *image.RGBA) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if dst.Rect.Dx() != c.w || dst.Rect.Dy() != c.h {
		return fmt.Errorf("dst size mismatch: dst=%dx%d fb=%dx%d",
			dst.Rect.Dx(), dst.Rect.Dy(), c.w, c.h)
	}
	switch c.bpp {
	case 32:
		// vt(4) on KMS framebuffers is BGRA: byte 0=B, 1=G, 2=R.
		swizzleBGRAtoRGBA(dst.Pix, c.mmap[:c.h*c.stride])
	case 24:
		swizzleFB24(dst.Pix, dst.Stride, c.mmap, c.stride, c.w, c.h)
	case 16:
		swizzleFB16RGB565(dst.Pix, dst.Stride, c.mmap, c.stride, c.w, c.h)
	}
	return nil
}

// Close releases the framebuffer mmap and file descriptor. Serialized with
// CaptureInto via c.mu so an in-flight capture can't read freed memory.
func (c *FBCapturer) Close() {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.mmap != nil {
			_ = unix.Munmap(c.mmap)
			c.mmap = nil
		}
		if c.fd >= 0 {
			_ = unix.Close(c.fd)
			c.fd = -1
		}
	})
}
