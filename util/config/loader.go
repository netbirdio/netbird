// Package config loads service configuration from defaults, files, environment
// variables, and command-line flags. Values are applied in that order, so an
// explicitly changed flag has the highest precedence.
//
// Configuration keys come from the struct tag selected by [Options.TagName],
// which defaults to "mapstructure". Environment variable names are inferred
// from those keys with the NB prefix. For example, server.listen-address maps
// to NB_SERVER_LISTEN_ADDRESS. The env and flag tags can provide explicit names,
// comma-separated compatibility aliases, or "-" to disable a source.
//
// A typical service configuration can be loaded as follows:
//
//	type Config struct {
//		Address string        `yaml:"address" env:"NB_ADDRESS" flag:"address"`
//		Timeout time.Duration `yaml:"timeout"`
//	}
//
//	flags := pflag.NewFlagSet("service", pflag.ContinueOnError)
//	flags.String("address", ":443", "service listen address")
//
//	cfg, err := config.Load("config.yaml", &Config{
//		Address: ":443",
//		Timeout: 30 * time.Second,
//	}, config.Options{
//		TagName: "yaml",
//		FlagSet: flags,
//		Strict:  true,
//	})
//
// Set [Options.AllowMissing] when the service must start without a configuration
// file. [Options.Transform] can preprocess file contents before decoding, such
// as with [ExpandEnvTemplate].
package config

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const envPrefix = "NB"

var (
	textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()
	jsonUnmarshalerType = reflect.TypeFor[json.Unmarshaler]()
)

// Options controls how Load resolves files and fields.
type Options struct {
	// TagName selects the struct tag used for configuration keys.
	TagName string
	// AllowMissing permits an empty path or a file that does not exist.
	AllowMissing bool
	// FlagSet provides command-line flags referenced by `flag` struct tags.
	FlagSet *pflag.FlagSet
	// Transform rewrites configuration file contents before decoding.
	Transform func([]byte) ([]byte, error)
	// Strict rejects configuration keys that are not represented by the target type.
	Strict bool
}

// Load reads configuration into a default-initialized value. Environment values
// override file values, and file values override defaults.
func Load[T any](configPath string, cfg *T, options Options) (*T, error) {
	if cfg == nil {
		return nil, fmt.Errorf("default config is nil")
	}

	configType := reflect.TypeFor[T]()
	if configType.Kind() != reflect.Struct {
		return nil, fmt.Errorf("config type %s must be a struct", configType)
	}

	if configPath == "" && !options.AllowMissing {
		return nil, errors.New("config file path is required")
	}

	tagName := options.TagName
	if tagName == "" {
		tagName = "mapstructure"
	}

	configData, err := readConfigFile(configPath, options.AllowMissing)
	if err != nil {
		return nil, err
	}

	configFormat := ""
	if configData != nil {
		configFormat, err = resolveConfigType(configPath, tagName)
		if err != nil {
			return nil, err
		}
		if options.Transform != nil {
			configData, err = options.Transform(configData)
			if err != nil {
				return nil, fmt.Errorf("transform config: %w", err)
			}
		}
	}

	v := viper.New()
	if configFormat != "" {
		v.SetConfigType(configFormat)
	}
	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AllowEmptyEnv(true)
	v.AutomaticEnv()

	if err := bindConfigSources(
		v,
		configType,
		"",
		tagName,
		options.FlagSet,
		true,
		true,
		make(map[reflect.Type]bool),
	); err != nil {
		return nil, fmt.Errorf("bind config sources: %w", err)
	}

	if configData != nil {
		if err := v.ReadConfig(bytes.NewReader(configData)); err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	var unmarshalErr error
	if options.Strict {
		unmarshalErr = v.UnmarshalExact(cfg, decoderConfig(tagName))
	} else {
		unmarshalErr = v.Unmarshal(cfg, decoderConfig(tagName))
	}
	if unmarshalErr != nil {
		return nil, fmt.Errorf("unmarshal config: %w", unmarshalErr)
	}
	return cfg, nil
}

func readConfigFile(configPath string, allowMissing bool) ([]byte, error) {
	if configPath == "" {
		return nil, nil
	}

	data, err := os.ReadFile(configPath)
	if err == nil {
		return data, nil
	}
	if allowMissing && errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return nil, fmt.Errorf("read config file: %w", err)
}

func resolveConfigType(configPath, fallbackType string) (string, error) {
	extension := strings.TrimPrefix(strings.ToLower(filepath.Ext(configPath)), ".")
	if slices.Contains(viper.SupportedExts, extension) {
		return extension, nil
	}

	fallbackType = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(fallbackType)), ".")
	if fallbackType != "" {
		if !slices.Contains(viper.SupportedExts, fallbackType) {
			return "", fmt.Errorf("unsupported default config type %q", fallbackType)
		}
		return fallbackType, nil
	}

	if extension == "" {
		return "", errors.New("config file extension is required")
	}
	return "", fmt.Errorf("unsupported config file extension %q", extension)
}

func decoderConfig(tagName string) viper.DecoderConfigOption {
	return func(config *mapstructure.DecoderConfig) {
		config.TagName = tagName
		config.DecodeHook = mapstructure.ComposeDecodeHookFunc(
			decodeLegacyBoolean,
			mapstructure.TextUnmarshallerHookFunc(),
			jsonUnmarshallerHook,
			config.DecodeHook,
		)
	}
}

func bindConfigSources(
	v *viper.Viper,
	configType reflect.Type,
	prefix string,
	tagName string,
	flagSet *pflag.FlagSet,
	bindEnvironment bool,
	bindFlags bool,
	visiting map[reflect.Type]bool,
) error {
	for configType.Kind() == reflect.Pointer {
		configType = configType.Elem()
	}
	visiting[configType] = true
	defer delete(visiting, configType)

	for i := range configType.NumField() {
		field := configType.Field(i)
		if !field.IsExported() {
			continue
		}

		key, inline, skip := configFieldKey(field, tagName)
		if skip {
			continue
		}
		if inline {
			key = prefix
		} else if prefix != "" {
			key = prefix + "." + key
		}

		fieldEnvironment := field.Tag.Get("env")
		fieldFlags := field.Tag.Get("flag")
		bindFieldEnvironment := bindEnvironment && fieldEnvironment != "-"
		bindFieldFlags := bindFlags && fieldFlags != "-"

		fieldType := field.Type
		for fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}
		if fieldType.Kind() == reflect.Struct && !isScalarUnmarshaler(fieldType) {
			if !visiting[fieldType] {
				if err := bindConfigSources(
					v,
					fieldType,
					key,
					tagName,
					flagSet,
					bindFieldEnvironment,
					bindFieldFlags,
					visiting,
				); err != nil {
					return err
				}
			}
			continue
		}

		if key == "" {
			return fmt.Errorf("empty config key for field %s", field.Name)
		}
		if bindFieldEnvironment {
			if err := bindEnvironmentVariable(v, key, fieldEnvironment); err != nil {
				return err
			}
		}
		if bindFieldFlags && flagSet != nil && fieldFlags != "" {
			flagName, flag, err := selectFlag(flagSet, fieldFlags)
			if err != nil {
				return fmt.Errorf("config field %s: %w", field.Name, err)
			}
			if err := v.BindPFlag(key, flag); err != nil {
				return fmt.Errorf("bind flag %s: %w", flagName, err)
			}
		}
	}
	return nil
}

func configFieldKey(field reflect.StructField, tagName string) (key string, inline, skip bool) {
	tagParts := strings.Split(field.Tag.Get(tagName), ",")
	key = tagParts[0]
	if key == "-" {
		return "", false, true
	}
	if key == "" {
		key = field.Name
	}
	for _, option := range tagParts[1:] {
		if option == "inline" || option == "squash" {
			inline = true
			break
		}
	}
	return key, inline, false
}

func selectFlag(flagSet *pflag.FlagSet, names string) (string, *pflag.Flag, error) {
	var selected *pflag.Flag
	selectedName := ""
	for _, name := range strings.Split(names, ",") {
		flag := flagSet.Lookup(name)
		if flag == nil {
			return "", nil, fmt.Errorf("references unknown flag %q", name)
		}
		if selected == nil || flag.Changed {
			selected = flag
			selectedName = name
		}
		if flag.Changed {
			break
		}
	}
	return selectedName, selected, nil
}

func bindEnvironmentVariable(v *viper.Viper, key, environmentName string) error {
	var err error
	if environmentName == "" {
		err = v.BindEnv(key)
	} else {
		names := strings.Split(environmentName, ",")
		arguments := append([]string{key}, names...)
		err = v.BindEnv(arguments...)
	}
	if err != nil {
		return fmt.Errorf("bind environment for %s: %w", key, err)
	}
	return nil
}

func isScalarUnmarshaler(configType reflect.Type) bool {
	return implements(configType, textUnmarshalerType) ||
		implements(configType, jsonUnmarshalerType)
}

func implements(configType, interfaceType reflect.Type) bool {
	return configType.Implements(interfaceType) ||
		reflect.PointerTo(configType).Implements(interfaceType)
}

func jsonUnmarshallerHook(from, to reflect.Type, data any) (any, error) {
	if !implements(to, jsonUnmarshalerType) {
		return data, nil
	}

	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	targetType := to
	if targetType.Kind() == reflect.Pointer {
		targetType = targetType.Elem()
	}
	target := reflect.New(targetType)
	unmarshaler, ok := target.Interface().(json.Unmarshaler)
	if !ok {
		return data, nil
	}
	if err := unmarshaler.UnmarshalJSON(raw); err != nil {
		return nil, err
	}
	if to.Kind() == reflect.Pointer {
		return target.Interface(), nil
	}
	return target.Elem().Interface(), nil
}

func decodeLegacyBoolean(from, to reflect.Kind, data any) (any, error) {
	if from != reflect.String || to != reflect.Bool {
		return data, nil
	}

	switch strings.ToLower(data.(string)) {
	case "y", "yes", "on":
		return true, nil
	case "n", "no", "off":
		return false, nil
	default:
		return data, nil
	}
}
