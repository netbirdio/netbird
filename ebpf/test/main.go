package main

// This code is derived from https://github.com/cloudflare/cloudflare-blog/tree/master/2018-03-ebpf
//
// Copyright (c) 2015-2017 Cloudflare, Inc. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of the Cloudflare, Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import (
	"fmt"
	"net"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// ExampleExtractDistance shows how to attach an eBPF socket filter to
// extract the network distance of an IP host.
func main() {
	filter, TTLs, err := newDistanceFilter()
	if err != nil {
		panic(err)
	}
	defer filter.Close()
	defer TTLs.Close()

	// Attach filter before the call to connect()
	dialer := net.Dialer{
		Control: func(network, address string, c syscall.RawConn) (err error) {
			const SO_ATTACH_BPF = 50

			err = c.Control(func(fd uintptr) {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_ATTACH_BPF, filter.FD())
			})
			return err
		},
	}

	conn, err := dialer.Dial("tcp", "1.1.1.1:53")
	if err != nil {
		panic(err)
	}
	conn.Close()

	minDist, err := minDistance(TTLs)
	if err != nil {
		panic(err)
	}

	fmt.Println("1.1.1.1:53 is", minDist, "hops away")
}

func newDistanceFilter() (*ebpf.Program, *ebpf.Map, error) {
	const ETH_P_IPV6 uint16 = 0x86DD

	ttls, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 4,
	})
	if err != nil {
		return nil, nil, err
	}

	insns := asm.Instructions{
		// r1 has ctx
		// r0 = ctx[16] (aka protocol)
		asm.LoadMem(asm.R0, asm.R1, 16, asm.Word),

		// Perhaps ipv6
		asm.LoadImm(asm.R2, int64(ETH_P_IPV6), asm.DWord),
		asm.HostTo(asm.BE, asm.R2, asm.Half),
		asm.JEq.Reg(asm.R0, asm.R2, "ipv6"),

		// otherwise assume ipv4
		// 8th byte in IPv4 is TTL
		// LDABS requires ctx in R6
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadAbs(-0x100000+8, asm.Byte),
		asm.Ja.Label("store-ttl"),

		// 7th byte in IPv6 is Hop count
		// LDABS requires ctx in R6
		asm.Mov.Reg(asm.R6, asm.R1).Sym("ipv6"),
		asm.LoadAbs(-0x100000+7, asm.Byte),

		// stash the load result into FP[-4]
		asm.StoreMem(asm.RFP, -4, asm.R0, asm.Word).Sym("store-ttl"),
		// stash the &FP[-4] into r2
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),

		// r1 must point to map
		asm.LoadMapPtr(asm.R1, ttls.FD()),
		asm.FnMapLookupElem.Call(),

		// load ok? inc. Otherwise? jmp to mapupdate
		asm.JEq.Imm(asm.R0, 0, "update-map"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		asm.Ja.Label("exit"),

		// MapUpdate
		// r1 has map ptr
		asm.LoadMapPtr(asm.R1, ttls.FD()).Sym("update-map"),
		// r2 has key -> &FP[-4]
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		// r3 has value -> &FP[-16] , aka 1
		asm.StoreImm(asm.RFP, -16, 1, asm.DWord),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -16),
		// r4 has flags, 0
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),

		// set exit code to -1, don't trunc packet
		asm.Mov.Imm(asm.R0, -1).Sym("exit"),
		asm.Return(),
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "distance_filter",
		Type:         ebpf.SocketFilter,
		License:      "GPL",
		Instructions: insns,
	})
	if err != nil {
		ttls.Close()
		return nil, nil, err
	}

	return prog, ttls, nil
}

func minDistance(TTLs *ebpf.Map) (int, error) {
	var (
		entries = TTLs.Iterate()
		ttl     uint32
		minDist uint32 = 255
		count   uint64
	)
	for entries.Next(&ttl, &count) {
		var dist uint32
		switch {
		case ttl > 128:
			dist = 255 - ttl
		case ttl > 64:
			dist = 128 - ttl
		case ttl > 32:
			dist = 64 - ttl
		default:
			dist = 32 - ttl
		}
		if minDist > dist {
			minDist = dist
		}
	}
	return int(minDist), entries.Err()
}
