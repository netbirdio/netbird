/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package bind

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// getSrcFromControl parses the control for PKTINFO and if found updates ep with
// the source information found.
func getSrcFromControl(control []byte, ep *StdNetEndpoint) {
	ep.ClearSrc()

	var (
		hdr  unix.Cmsghdr
		data []byte
		rem  []byte = control
		err  error
	)

	for len(rem) > unix.SizeofCmsghdr {
		hdr, data, rem, err = unix.ParseOneSocketControlMessage(control)
		if err != nil {
			return
		}

		if hdr.Level == unix.IPPROTO_IP &&
			hdr.Type == unix.IP_PKTINFO {

			info := pktInfoFromBuf[unix.Inet4Pktinfo](data)
			ep.src.Addr = netip.AddrFrom4(info.Spec_dst)
			ep.src.ifidx = info.Ifindex

			return
		}

		if hdr.Level == unix.IPPROTO_IPV6 &&
			hdr.Type == unix.IPV6_PKTINFO {

			info := pktInfoFromBuf[unix.Inet6Pktinfo](data)
			ep.src.Addr = netip.AddrFrom16(info.Addr)
			ep.src.ifidx = int32(info.Ifindex)

			return
		}
	}
}

// pktInfoFromBuf returns type T populated from the provided buf via copy(). It
// panics if buf is of insufficient size.
func pktInfoFromBuf[T unix.Inet4Pktinfo | unix.Inet6Pktinfo](buf []byte) (t T) {
	size := int(unsafe.Sizeof(t))
	if len(buf) < size {
		panic("pktInfoFromBuf: buffer too small")
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&t)), size), buf)
	return t
}

// setSrcControl parses the control for PKTINFO and if found updates ep with
// the source information found.
func setSrcControl(control *[]byte, ep *StdNetEndpoint) {
	*control = (*control)[:cap(*control)]
	if len(*control) < int(unsafe.Sizeof(unix.Cmsghdr{})) {
		*control = (*control)[:0]
		return
	}

	if ep.src.ifidx == 0 && !ep.SrcIP().IsValid() {
		*control = (*control)[:0]
		return
	}

	if len(*control) < srcControlSize {
		*control = (*control)[:0]
		return
	}

	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&(*control)[0]))
	if ep.SrcIP().Is4() {
		hdr.Level = unix.IPPROTO_IP
		hdr.Type = unix.IP_PKTINFO
		hdr.SetLen(unix.CmsgLen(unix.SizeofInet4Pktinfo))

		info := (*unix.Inet4Pktinfo)(unsafe.Pointer(&(*control)[unix.SizeofCmsghdr]))
		info.Ifindex = ep.src.ifidx
		if ep.SrcIP().IsValid() {
			info.Spec_dst = ep.SrcIP().As4()
		}
	} else {
		hdr.Level = unix.IPPROTO_IPV6
		hdr.Type = unix.IPV6_PKTINFO
		hdr.Len = unix.SizeofCmsghdr + unix.SizeofInet6Pktinfo

		info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&(*control)[unix.SizeofCmsghdr]))
		info.Ifindex = uint32(ep.src.ifidx)
		if ep.SrcIP().IsValid() {
			info.Addr = ep.SrcIP().As16()
		}
	}

	*control = (*control)[:hdr.Len]
}

var srcControlSize = unix.CmsgLen(unix.SizeofInet6Pktinfo)
