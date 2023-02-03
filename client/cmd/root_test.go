package cmd

import (
	"fmt"
	"io"
	"testing"
)

func TestInitCommands(t *testing.T) {
	helpFlag := "-h"
	commandArgs := [][]string{{"root", helpFlag}}
	for _, command := range rootCmd.Commands() {
		commandArgs = append(commandArgs, []string{command.Name(), command.Name(), helpFlag})
		for _, subcommand := range command.Commands() {
			commandArgs = append(commandArgs, []string{command.Name() + " " + subcommand.Name(), command.Name(), subcommand.Name(), helpFlag})
		}
	}

	for _, args := range commandArgs {
		t.Run(fmt.Sprintf("Testing Command %s", args[0]), func(t *testing.T) {
			defer func() {
				err := recover()
				if err != nil {
					t.Fatalf("got an panic error while running the command: %s -h. Error: %s", args[0], err)
				}
			}()

			rootCmd.SetArgs(args[1:])
			rootCmd.SetOut(io.Discard)
			if err := rootCmd.Execute(); err != nil {
				t.Errorf("expected no error while running %s command, got %v", args[0], err)
				return
			}
		})
	}
}
