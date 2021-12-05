package main

import (
	"encoding/hex"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"net"
)

const (
	SO_ATTACH_BPF   int    = 50
	StunMagicCookie uint32 = 0x2112A442
)

func main() {

	// open a raw socket
	/*fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		panic(err)
	}
	fmt.Print(fd)*/
	addr := net.UDPAddr{
		IP:   net.IPv4zero,
		Port: 12345,
	}
	conn, err := net.ListenUDP("udp4", &addr)
	if err != nil {
		return
	}

	filter := &Filter{
		ProgramSpec: &ebpf.ProgramSpec{
			Type:    ebpf.SocketFilter,
			License: "GPL",
			Instructions: asm.Instructions{
				asm.Mov.Reg(asm.R6, asm.R1), // LDABS requires ctx in R6
				asm.LoadAbs(-0x100000+22, asm.Half),
				asm.JNE.Imm(asm.R0, int32(addr.Port), "skip"),
				/*				asm.LoadAbs(-0x100000+32, asm.Word),
								asm.JNE.Imm(asm.R0, int32(StunMagicCookie), "skip"),
								asm.Mov.Imm(asm.R0, -1).Sym("exit"),*/
				/*asm.Return(),*/
				asm.Mov.Imm(asm.R0, 0).Sym("skip"),
				asm.Return(),
			},
		},
	}

	err = filter.ApplyTo(conn)
	if err != nil {
		panic(err)
	}

	fmt.Printf("start")
	buf := make([]byte, 1024)
	for {
		n, ra, err := conn.ReadFrom(buf)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Bytes read: %d\n", n)
		fmt.Printf("Remote Addr: %+v\n", ra)
		fmt.Printf("Bytes HEX: %s\n", hex.EncodeToString(buf[:n]))
		fmt.Printf("Bytes String: %s\n", string(buf[:n]))
		fmt.Println()
	}

}
