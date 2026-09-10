//go:build linux && !android

package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"sync"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Linux framebuffer ioctls (linux/fb.h).
const (
	fbioGetVScreenInfo = 0x4600
	fbioGetFScreenInfo = 0x4602
)

func defaultFBPath() string { return "/dev/fb0" }

// fbVarScreenInfo mirrors the kernel's fb_var_screeninfo. Only the
// fields we use are mapped; the rest are absorbed into _padN.
type fbVarScreenInfo struct {
	Xres, Yres                       uint32
	XresVirtual, YresVirtual         uint32
	XOffset, YOffset                 uint32
	BitsPerPixel                     uint32
	Grayscale                        uint32
	RedOffset, RedLen, RedMSBR       uint32
	GreenOffset, GreenLen, GreenMSBR uint32
	BlueOffset, BlueLen, BlueMSBR    uint32
	TranspOffset, TranspLen, TranspM uint32
	NonStd                           uint32
	Activate                         uint32
	Height, Width                    uint32
	AccelFlags                       uint32
	PixClock                         uint32
	LeftMargin, RightMargin          uint32
	UpperMargin, LowerMargin         uint32
	HsyncLen, VsyncLen               uint32
	Sync                             uint32
	Vmode                            uint32
	Rotate                           uint32
	Colorspace                       uint32
	_pad                             [4]uint32
}

// fbFixScreenInfo mirrors fb_fix_screeninfo. We only need LineLength.
//
// SmemStart and MmioStart are `unsigned long` in the kernel header, so they are
// pointer-sized: uintptr, not uint64. Spelling them uint64 would shift every
// field after SmemStart by four bytes on a 32-bit build and make LineLength
// read the wrong part of the ioctl's answer.
type fbFixScreenInfo struct {
	IDStr        [16]byte
	SmemStart    uintptr
	SmemLen      uint32
	Type         uint32
	TypeAux      uint32
	Visual       uint32
	XPanStep     uint16
	YPanStep     uint16
	YWrapStep    uint16
	_pad0        uint16
	LineLength   uint32
	MmioStart    uintptr
	MmioLen      uint32
	Accel        uint32
	Capabilities uint16
	_reserved    [2]uint16
}

// FBCapturer reads pixels straight from the Linux framebuffer device.
// Used as a fallback when X11 isn't available, e.g. on a headless box at
// the kernel console or the display manager's pre-login screen on machines
// without an Xorg server. The framebuffer must be mmap()-able under our
// process privileges (typically the netbird service runs as root).
type FBCapturer struct {
	mu        sync.Mutex
	path      string
	fd        int
	mmap      []byte
	w, h      int
	bpp       int
	stride    int
	rOff      uint32
	gOff      uint32
	bOff      uint32
	rLen      uint32
	gLen      uint32
	bLen      uint32
	closeOnce sync.Once
}

// NewFBCapturer opens the given framebuffer device (/dev/fbN) and
// queries its current geometry + pixel format.
func NewFBCapturer(path string) (*FBCapturer, error) {
	if path == "" {
		path = "/dev/fb0"
	}
	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	var vinfo fbVarScreenInfo
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), fbioGetVScreenInfo, uintptr(unsafe.Pointer(&vinfo))); e != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("FBIOGET_VSCREENINFO: %v", e)
	}
	var finfo fbFixScreenInfo
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), fbioGetFScreenInfo, uintptr(unsafe.Pointer(&finfo))); e != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("FBIOGET_FSCREENINFO: %v", e)
	}

	bpp := int(vinfo.BitsPerPixel)
	if bpp != 16 && bpp != 24 && bpp != 32 {
		unix.Close(fd)
		return nil, fmt.Errorf("unsupported framebuffer bpp: %d", bpp)
	}
	if err := validateFBLayout(bpp, &vinfo); err != nil {
		unix.Close(fd)
		return nil, err
	}

	size := int(finfo.LineLength) * int(vinfo.Yres)
	if size <= 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("invalid framebuffer dimensions: stride=%d h=%d", finfo.LineLength, vinfo.Yres)
	}

	mm, err := unix.Mmap(fd, 0, size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("mmap %s: %w", path, err)
	}

	c := &FBCapturer{
		path:   path,
		fd:     fd,
		mmap:   mm,
		w:      int(vinfo.Xres),
		h:      int(vinfo.Yres),
		bpp:    bpp,
		stride: int(finfo.LineLength),
		rOff:   vinfo.RedOffset,
		gOff:   vinfo.GreenOffset,
		bOff:   vinfo.BlueOffset,
		rLen:   vinfo.RedLen,
		gLen:   vinfo.GreenLen,
		bLen:   vinfo.BlueLen,
	}
	log.Infof("framebuffer capturer ready: %s %dx%d bpp=%d r=%d/%d g=%d/%d b=%d/%d",
		path, c.w, c.h, c.bpp, c.rOff, c.rLen, c.gOff, c.gLen, c.bOff, c.bLen)
	return c, nil
}

// validateFBLayout refuses a pixel layout the swizzlers do not implement.
//
// Each swizzler is written for one layout: 32bpp reads whole channels at the
// queried offsets, 24bpp reads packed B,G,R triplets, and 16bpp reads RGB565.
// A device reporting anything else (RGB888 at 24bpp, BGR565, a 10-bit channel)
// would be swizzled into wrong colours, which is worse than declining to
// capture at all, because nothing downstream can tell that it happened.
func validateFBLayout(bpp int, v *fbVarScreenInfo) error {
	unsupported := func() error {
		return fmt.Errorf("unsupported %dbpp framebuffer layout: r=%d/%d g=%d/%d b=%d/%d",
			bpp, v.RedOffset, v.RedLen, v.GreenOffset, v.GreenLen, v.BlueOffset, v.BlueLen)
	}

	// msb_right marks a channel whose bits run the other way inside the pixel.
	// Every swizzler reads them in normal order, so such a device would be
	// decoded into mirrored channel values.
	if v.RedMSBR != 0 || v.GreenMSBR != 0 || v.BlueMSBR != 0 {
		return fmt.Errorf("unsupported %dbpp framebuffer layout: msb_right set (r=%d g=%d b=%d)",
			bpp, v.RedMSBR, v.GreenMSBR, v.BlueMSBR)
	}

	switch bpp {
	case 32:
		// Offsets are honoured, channel widths are not.
		if v.RedLen != 8 || v.GreenLen != 8 || v.BlueLen != 8 {
			return unsupported()
		}
	case 24:
		if v.RedLen != 8 || v.GreenLen != 8 || v.BlueLen != 8 ||
			v.BlueOffset != 0 || v.GreenOffset != 8 || v.RedOffset != 16 {
			return unsupported()
		}
	case 16:
		if v.RedOffset != 11 || v.RedLen != 5 ||
			v.GreenOffset != 5 || v.GreenLen != 6 ||
			v.BlueOffset != 0 || v.BlueLen != 5 {
			return unsupported()
		}
	}
	return nil
}

// Width returns the framebuffer width in pixels.
func (c *FBCapturer) Width() int { return c.w }

// Height returns the framebuffer height in pixels.
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

// CaptureInto reads the framebuffer directly into dst.Pix.
func (c *FBCapturer) CaptureInto(dst *image.RGBA) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close unmaps but leaves w/h in place, so a capture arriving afterwards
	// would pass the size check below and index into a nil mapping.
	if c.mmap == nil {
		return errors.New("framebuffer capturer is closed")
	}

	if dst.Rect.Dx() != c.w || dst.Rect.Dy() != c.h {
		return fmt.Errorf("dst size mismatch: dst=%dx%d fb=%dx%d",
			dst.Rect.Dx(), dst.Rect.Dy(), c.w, c.h)
	}

	switch c.bpp {
	case 32:
		swizzleFB32(dst.Pix, dst.Stride, c.mmap, c.stride, c.w, c.h, channelShifts{R: c.rOff, G: c.gOff, B: c.bOff})
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

// channelShifts groups the bit offsets for the R/G/B channels in a packed
// uint32 framebuffer pixel. Bundling avoids drowning per-row callers in a
// 9-parameter signature.
type channelShifts struct {
	R, G, B uint32
}

// swizzleFB32 handles 32-bit framebuffers with arbitrary R/G/B channel
// offsets. Pulls one pixel per uint32, then masks each channel into the
// destination RGBA byte order.
func swizzleFB32(dst []byte, dstStride int, src []byte, srcStride, w, h int, shifts channelShifts) {
	for y := 0; y < h; y++ {
		srcRow := src[y*srcStride : y*srcStride+w*4]
		dstRow := dst[y*dstStride:]
		for x := 0; x < w; x++ {
			pix := binary.LittleEndian.Uint32(srcRow[x*4 : x*4+4])
			dstRow[x*4+0] = byte(pix >> shifts.R)
			dstRow[x*4+1] = byte(pix >> shifts.G)
			dstRow[x*4+2] = byte(pix >> shifts.B)
			dstRow[x*4+3] = 0xff
		}
	}
}
