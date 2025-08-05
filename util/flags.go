package util

import (
	"os"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// setFlagsFromEnvVars reads and updates flag values from environment variables with prefix WT_
func SetFlagsFromEnvVars(cmd *cobra.Command) {
	// Fetch the credentials directory if it exists
	credsDir, present := os.LookupEnv("CREDENTIALS_DIRECTORY")

	flags := cmd.PersistentFlags()
	flags.VisitAll(func(f *pflag.Flag) {
		name := flagNameToUpper(f.Name)

		// Try to get the value from the credential directory
		if present {
			data, e := os.ReadFile(path.Join(credsDir, name))

			if e == nil {
				err := flags.Set(f.Name, strings.TrimSuffix(string(data), "\n"))

				if err != nil {
					log.Infof("unable to configure flag %s using credential %s, err: %v", f.Name, name, err)
				} else {
					return
				}
			}
		}

		// Fallback to env variable, which is constructed by adding the required prefix
		// E.g. SETUP_KEYS -> NB_SETUP_KEYS
		envName := "NB_" + name

		if value, varPresent := os.LookupEnv(envName); varPresent {
			err := flags.Set(f.Name, value)

			if err != nil {
				log.Infof("unable to configure flag %s using variable %s, err: %v", f.Name, envName, err)
			}
		}
	})
}

// flagNameToUpper converts a flag name to its corresponding base env name
// replacing dashes by underscores and making the result uppercase
// E.g. setup-keys -> SETUP_KEYS
func flagNameToUpper(cmdFlag string) string {
	return strings.ToUpper(strings.ReplaceAll(cmdFlag, "-", "_"))
}
