//go:build !windows

package cmd

import (
	"github.com/spf13/cobra"
)

var updateCmd *cobra.Command

func isUpdateBinary() bool {
	return false
}
