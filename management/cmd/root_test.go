package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestCustomize verifies an embedding binary can extend the command tree: a
// top-level command attached through the hook, and a subcommand attached under
// the built-in admin group, are both resolvable exactly as Execute would
// resolve them.
func TestCustomize(t *testing.T) {
	topLevel := &cobra.Command{Use: "some-extra", RunE: func(*cobra.Command, []string) error { return nil }}
	nested := &cobra.Command{Use: "cluster", RunE: func(*cobra.Command, []string) error { return nil }}

	Customize(func(root *cobra.Command) {
		root.AddCommand(topLevel)
		for _, c := range root.Commands() {
			if c.Name() == "admin" {
				c.AddCommand(nested)
				return
			}
		}
		t.Fatal("admin command not found in the root tree")
	})
	t.Cleanup(func() {
		rootCmd.RemoveCommand(topLevel)
		for _, c := range rootCmd.Commands() {
			if c.Name() == "admin" {
				c.RemoveCommand(nested)
			}
		}
	})

	if found, _, err := rootCmd.Find([]string{"some-extra"}); err != nil || found != topLevel {
		t.Fatalf("top-level command not resolvable: found=%v err=%v", found, err)
	}
	if found, _, err := rootCmd.Find([]string{"admin", "cluster"}); err != nil || found != nested {
		t.Fatalf("nested admin subcommand not resolvable: found=%v err=%v", found, err)
	}
}
