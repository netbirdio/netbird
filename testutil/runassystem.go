package main

import (
	"fmt"
	"os"
	"os/exec"

	"golang.zx2c4.com/wireguard/windows/elevate"
)

func main() {
	argsWithoutProg := os.Args[1:]
	op := func() error {
		cmd := exec.Command(argsWithoutProg[0], argsWithoutProg[1:]...)
		out, err := cmd.Output()
		fmt.Println("")
		fmt.Printf(string(out))
		if err != nil {
			return err
		}
		return nil
	}
	fmt.Println(elevate.DoAsService("netbird", op))
}
