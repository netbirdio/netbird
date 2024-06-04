package main

import (
	"fmt"

	"github.com/hashicorp/go-version"
)

func main() {
	fmt.Println(version.NewVersion(""))
}
