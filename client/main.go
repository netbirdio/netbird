package main

import (
	"C"
	"fmt"
	"os"

	"github.com/wiretrustee/wiretrustee/client/cmd"
)
import (
	"unsafe"
)

// no space before export!
//export run
func run(setupKey string) {
	// Don't block UI thread
	// TODO add error checking
	go func() {
		fmt.Printf("Go run called!")
		os.Args = []string{"this.exe", "login", "--config=config.json", "--setup-key=" + setupKey}
		if err := cmd.Execute(); err != nil {
			fmt.Println("Login failed ", err)
			return
			// os.Exit(1)
		}

		fmt.Printf("Go Login succeeded!")
		os.Args = []string{"this.exe", "up", "--config=config.json", "--management-only=true"}
		if err := cmd.Execute(); err != nil {
			fmt.Println("Up failed ", err)
			return
			// os.Exit(1)
		}

		fmt.Println("Go Finished!")
	}()
}

// no space before export!
//export getPeers
func getPeers(cnt *int) **C.char {
	if cmd.Engine == nil {
		// Not initialized yet
		//TODO add mutex for cmd.Engine
		*cnt = 0
		return nil
	}

	peers := cmd.Engine.GetPeers()
	fmt.Println("Number of peers ", len(peers))

	count := len(peers)
	c_count := C.int(count)

	cArray := C.malloc(C.size_t(c_count) * C.size_t(unsafe.Sizeof(uintptr(0))))

	// convert the C array to a Go Array so we can index it
	a := (*[1<<30 - 1]*C.char)(cArray)
	for index, value := range peers {
		a[index] = C.CString(value)
	}

	*cnt = count
	return (**C.char)(unsafe.Pointer(cArray))
}

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
