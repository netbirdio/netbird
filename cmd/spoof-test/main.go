package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/netbirdio/netbird/client/system"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func main() {
	var info *system.Info
	if len(os.Args) > 1 {
		checks := []*mgmProto.Checks{
			{Files: os.Args[1:]},
		}
		var err error
		info, err = system.GetInfoWithChecks(context.Background(), checks)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error gathering info with checks: %v\n", err)
			os.Exit(1)
		}
	} else {
		info = system.GetInfo(context.Background())
	}

	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stdout, string(data))
}
