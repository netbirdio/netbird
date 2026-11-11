package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const requiresFlagAnnotation = "netbird_requires_flag"

// markFlagRequires records that flag on cmd only has an effect together with
// required. It panics if flag is not defined on cmd, like cobra's own flag groups.
func markFlagRequires(cmd *cobra.Command, flag, required string) {
	f := cmd.Flags().Lookup(flag)
	if f == nil {
		panic(fmt.Sprintf("mark flag %q as requiring %q: flag not defined", flag, required))
	}
	requirements := append(f.Annotations[requiresFlagAnnotation], required)
	if err := cmd.Flags().SetAnnotation(flag, requiresFlagAnnotation, requirements); err != nil {
		panic(fmt.Sprintf("mark flag %q as requiring %q: %v", flag, required, err))
	}
}

// commandLineFlags returns the flags set on cmd's command line. It must run
// before SetFlagsFromEnvVars marks environment-set flags as changed.
func commandLineFlags(cmd *cobra.Command) map[string]bool {
	set := make(map[string]bool)
	cmd.Flags().Visit(func(f *pflag.Flag) {
		set[f.Name] = true
	})
	return set
}

// validateFlagRequirements fails when a flag set on the command line is used
// without the flag it requires. Only command-line flags are checked, so a
// variable exported in the shell does not break commands that ignore it.
// The required flag may come from the command line or the environment.
func validateFlagRequirements(cmd *cobra.Command, setOnCommandLine map[string]bool) error {
	var err error
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if err != nil || !setOnCommandLine[f.Name] {
			return
		}
		for _, required := range f.Annotations[requiresFlagAnnotation] {
			if !isFlagEnabled(cmd, required) {
				err = fmt.Errorf("--%s requires --%s", f.Name, required)
				return
			}
		}
	})
	return err
}

// isFlagEnabled reports whether name is set and, for a boolean flag, true.
func isFlagEnabled(cmd *cobra.Command, name string) bool {
	f := cmd.Flag(name)
	if f == nil || !f.Changed {
		return false
	}
	return f.Value.Type() != "bool" || f.Value.String() == "true"
}
