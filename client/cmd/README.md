# Adding CLI commands, flags and environment variables

New CLI or service flags are a high-risk area. The following sections provide a guide for developers adding CLI commands, flags, and environment variables on the daemon or client side.

## Pick the kind

| What you are adding | Use | Saved in |
| --- | --- | --- |
| A new action | Command or subcommand | Nothing |
| A per-profile client setting | Flag on `up` (and `login` if it applies at login) | The profile, through the daemon |
| How the daemon process runs | Flag added in `addDaemonFlags` | `service.json` |
| An option for a single run | Local flag on that command | Nothing |
| Tuning, debugging, an experiment, a workaround, legacy purposes | Env var only, no flag | Nothing |
| A setting admins must enforce | MDM key, in addition to the flag | The MDM policy |

A command is a verb (`netbird expose`). Group related commands under a parent noun (`netbird profile add`). Prefer a flag over a new command when it only changes how an existing action runs.

## Precedence

MDM > env vars (both local and flag) > flag > profile > management > default.

- Flags on commands under `rootCmd` get an `NB_` (or legacy `WT_`) environment variable automatically; standalone updater flags do not, so wire those explicitly if needed.
- A feature that exposes the device (SSH, remote jobs, routes) is enabled by management. Local layers and MDM can only switch it off, never on by themselves.
- Don't add new exceptions to this order (lazy connections is the only one).

## Add a command

```go
var fooCmd = &cobra.Command{
	Use:   "foo <peer>",
	Short: "One line, starting with a verb",
	Args:  cobra.ExactArgs(1),
	RunE:  fooFunc,
}

func init() {
	rootCmd.AddCommand(fooCmd)
}
```

- Use `RunE` and return errors. Don't print them and exit.
- Validate arguments with `Args` (`cobra.NoArgs`, `cobra.ExactArgs`, `cobra.RangeArgs`).
- Don't add a `PersistentPreRunE`. It would replace the root hook that applies env vars and checks flag requirements.

## Add a flag

- Name it in kebab case and keep the name in a constant when more than one file reads it.
- Use `cmd.Flags()` by default. Use `PersistentFlags()` only when every subcommand reads the flag.
- Share a flag between commands through an `add<Name>Flag(cmd)` helper (see `addLoginFlags` and `addDaemonFlags`).
- Use `cmd.Flag(name).Changed` to tell "set to the default value" apart from "not set". Client settings only send changed values to the daemon.
- For a client setting, copy the flag in all three places in `up.go`: `setupSetConfigReq`, `setupLoginRequest` and `setupConfig` (foreground mode).
- For a daemon setting, add it to `serviceParams`, `currentServiceParams`, `applyServiceParams` and `buildServiceArguments`.
- Prefer not to remove a flag. Use `MarkDeprecated`, or `MarkHidden` for one that is kept only so existing service arguments keep working.

## Add an env var (no flag)

- The name starts with `NB_` and lives in a constant.
- Parse booleans with `strconv.ParseBool` and, on error, log only the variable name and a generic invalid-boolean message; never log the raw parse error because it includes the value.
- Read it where it is used. The daemon only sees it through `netbird service install --service-env`.
- Prefer MDM over env vars.

## Check flag combinations

Every new flag must be checked against the existing flags of its command. A combination where one flag is silently ignored is a bug.

| Rule | Use |
| --- | --- |
| Only one of the flags can be set | `cmd.MarkFlagsMutuallyExclusive(a, b)` |
| Flag a only works with flag b | `markFlagRequires(cmd, a, b)`, only for flags that are not saved |
| All of the flags or none of them | `cmd.MarkFlagsRequiredTogether(a, b)` |
| At least one of the flags | `cmd.MarkFlagsOneRequired(a, b)` |
| The flag is always needed | `cmd.MarkFlagRequired(a)` |

- Mention the rule in the help text, for example "Cannot be used with --setup-key".
- `markFlagRequires` can't be used when the required value may already be saved (`up` settings, `service reconfigure`). Check those in `RunE` after loading the saved values.
- When the rule depends on a flag's value rather than whether it is set, check it in `RunE`.
- Groups and requirements are checked after env vars are applied. An environment value satisfies a required flag. An environment-set flag does not trigger its own requirement, because `validateFlagRequirements` checks only flags set on the command line.

## Before opening the PR

- Commands that change settings respect `--disable-update-settings` and the matching MDM keys. The daemon enforces that, not the CLI.
- Any new daemon RPC field is untrusted input and is gated in the handler (see `AGENTS.md`).
- Add tests for the flag registration and any combination rules.
- Open a docs PR that updates the CLI reference and the environment variable page.
