package main

import (
	"C"
	"fmt"
	"os"

	"github.com/wiretrustee/wiretrustee/client/cmd"
)

// no space before export!
//export run
func run(setupKey string) {
	fmt.Printf("Go run called!")
	os.Args = []string{"this.exe", "login", "--config=config.json", "--setup-key=" + setupKey}
	if err := cmd.Execute(); err != nil {
		fmt.Printf("Login failed %s", err)
		return
		// os.Exit(1)
	}

	fmt.Printf("Go Login succeeded!")
	os.Args = []string{"this.exe", "up", "--config=config.json", "--management-only=true"}
	if err := cmd.Execute(); err != nil {
		fmt.Printf("Up failed %s", err)
		return
		// os.Exit(1)
	}

	fmt.Printf("Go Finished!")
}

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
