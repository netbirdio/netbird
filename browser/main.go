package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	log.Print("listening on http://localhost:9090")
	err := http.ListenAndServe(":9090", http.FileServer(http.Dir("./assets")))
	//err := http.ListenAndServe(":9090", http.FileServer(http.Dir("/home/braginini/Documents/projects/my/wiretrustee/rtctunnel/examples/browser-http/dist")))

	if err != nil {
		fmt.Println("Failed to start server", err)
		return
	}
}
