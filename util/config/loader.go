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
// file. [Options.Transform] can preprocess file contents before decoding.
package config

import (
	"bytes"
	"encoding"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var (
	textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()
	jsonUnmarshalerType = reflect.TypeFor[json.Unmarshaler]()
)

// InvalidEnvironmentAction controls how invalid environment values are handled.
type InvalidEnvironmentAction uint8

const (
	// InvalidEnvironmentFatal returns the parsing error.
	InvalidEnvironmentFatal InvalidEnvironmentAction = iota
	// InvalidEnvironmentIgnore keeps the file or default value.
	InvalidEnvironmentIgnore
	// InvalidEnvironmentUsePartial keeps scalar values returned with parsing errors.
	InvalidEnvironmentUsePartial
)

// Options controls how Load resolves files and fields.
type Options struct {
	// TagName selects the struct tag and decoder used for configuration keys.
	TagName string
	// AllowMissing permits an empty path or a file that does not exist.
	AllowMissing bool
	// FlagSet provides command-line flags referenced by `flag` struct tags.
	FlagSet *pflag.FlagSet
	// Transform rewrites configuration file contents before decoding.
	Transform func([]byte) ([]byte, error)
	// Strict rejects configuration keys that are not represented by the target type.
	Strict bool
	// InvalidEnvironment controls how parsing failures affect the loaded value.
	InvalidEnvironment InvalidEnvironmentAction
	// DecodeErrorPrefix preserves service-specific context for file decoding errors.
	DecodeErrorPrefix string
}

// Load reads configuration into a default-initialized value. Explicitly tagged
// environment values and changed flags override file values.
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
	if configData != nil {
		if options.Transform != nil {
			configData, err = options.Transform(configData)
			if err != nil {
				return nil, fmt.Errorf("transform config: %w", err)
			}
		}
		if err := decodeConfigFile(configData, cfg, tagName, options.Strict); err != nil {
			if options.DecodeErrorPrefix != "" {
				return nil, fmt.Errorf("%s: %w", options.DecodeErrorPrefix, err)
			}
			return nil, err
		}
	}

	v := viper.New()
	v.AllowEmptyEnv(true)

	if err := bindConfigSources(
		v,
		configType,
		"",
		tagName,
		options.FlagSet,
		options.InvalidEnvironment,
		true,
		true,
		make(map[reflect.Type]bool),
	); err != nil {
		return nil, fmt.Errorf("bind config sources: %w", err)
	}

	if err := v.Unmarshal(cfg, decoderConfig(tagName)); err != nil {
		return nil, fmt.Errorf("unmarshal config overlay: %w", err)
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
func decodeConfigFile(data []byte, cfg any, tagName string, strict bool) error {
	switch tagName {
	case "json":
		decoder := json.NewDecoder(bytes.NewReader(data))
		if strict {
			decoder.DisallowUnknownFields()
		}
		if err := decoder.Decode(cfg); err != nil {
			return err
		}
		return nil
	case "yaml":
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(strict)
		if err := decoder.Decode(cfg); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unsupported config decoder %q", tagName)
	}
}
func decoderConfig(tagName string) viper.DecoderConfigOption {
	return func(config *mapstructure.DecoderConfig) {
		config.TagName = tagName
		config.Squash = true
		config.DecodeHook = mapstructure.ComposeDecodeHookFunc(
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
	invalidEnvironment InvalidEnvironmentAction,
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
		if err := bindConfigField(
			v,
			configType.Field(i),
			prefix,
			tagName,
			flagSet,
			invalidEnvironment,
			bindEnvironment,
			bindFlags,
			visiting,
		); err != nil {
			return err
		}
	}
	return nil
}

func bindConfigField(
	v *viper.Viper,
	field reflect.StructField,
	prefix string,
	tagName string,
	flagSet *pflag.FlagSet,
	invalidEnvironment InvalidEnvironmentAction,
	bindEnvironment bool,
	bindFlags bool,
	visiting map[reflect.Type]bool,
) error {
	if !field.IsExported() {
		return nil
	}

	key, inline, skip := configFieldKey(field, tagName)
	if skip {
		return nil
	}
	if inline {
		key = prefix
	} else if prefix != "" {
		key = prefix + "." + key
	}

	fieldEnvironment := field.Tag.Get("env")
	fieldFlags := field.Tag.Get("flag")
	bindEnvironment = bindEnvironment && fieldEnvironment != "-"
	bindFlags = bindFlags && fieldFlags != "-"

	fieldType := field.Type
	for fieldType.Kind() == reflect.Pointer {
		fieldType = fieldType.Elem()
	}
	if fieldType.Kind() == reflect.Struct && !isScalarUnmarshaler(fieldType) {
		if visiting[fieldType] {
			return nil
		}
		return bindConfigSources(
			v,
			fieldType,
			key,
			tagName,
			flagSet,
			invalidEnvironment,
			bindEnvironment,
			bindFlags,
			visiting,
		)
	}

	return bindScalarSources(
		v,
		field,
		key,
		fieldEnvironment,
		fieldFlags,
		flagSet,
		invalidEnvironment,
		bindEnvironment,
		bindFlags,
	)
}

func bindScalarSources(
	v *viper.Viper,
	field reflect.StructField,
	key string,
	environmentNames string,
	flagNames string,
	flagSet *pflag.FlagSet,
	invalidEnvironment InvalidEnvironmentAction,
	bindEnvironment bool,
	bindFlags bool,
) error {
	if key == "" {
		return fmt.Errorf("empty config key for field %s", field.Name)
	}

	var environmentValue any
	environmentSet := false
	if bindEnvironment && environmentNames != "" {
		value, set, err := environmentValueForField(
			v,
			key,
			environmentNames,
			field.Type,
			invalidEnvironment,
		)
		if err != nil {
			return fmt.Errorf("environment for %s: %w", key, err)
		}
		environmentValue = value
		environmentSet = set
	}

	var flag *pflag.Flag
	if bindFlags && flagSet != nil && flagNames != "" {
		flagName, selected, err := selectFlag(flagSet, flagNames)
		if err != nil {
			return fmt.Errorf("config field %s: %w", field.Name, err)
		}
		flag = selected
		if flag != nil {
			if err := v.BindPFlag(key, flag); err != nil {
				return fmt.Errorf("bind flag %s: %w", flagName, err)
			}
		}
	}

	switch {
	case environmentSet && flag != nil && indirectKind(field.Type) == reflect.Slice:
		flagValue, err := parsedFlagValue(field.Type, flag)
		if err != nil {
			return fmt.Errorf("parse flag %s: %w", flag.Name, err)
		}
		combined := reflect.AppendSlice(reflect.ValueOf(environmentValue), reflect.ValueOf(flagValue))
		v.Set(key, combined.Interface())
	case environmentSet && flag == nil:
		v.Set(key, environmentValue)
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
	for _, name := range strings.Split(names, ",") {
		flag := flagSet.Lookup(name)
		if flag == nil {
			return "", nil, fmt.Errorf("references unknown flag %q", name)
		}
		if flag.Changed {
			return name, flag, nil
		}
	}
	return "", nil, nil
}

func environmentValueForField(
	v *viper.Viper,
	key string,
	environmentNames string,
	fieldType reflect.Type,
	action InvalidEnvironmentAction,
) (any, bool, error) {
	for _, name := range strings.Split(environmentNames, ",") {
		value, present := os.LookupEnv(name)
		if !present {
			continue
		}
		if value == "" && indirectKind(fieldType) != reflect.String {
			return nil, false, nil
		}

		parsed, partial, err := parseScalarValue(fieldType, value)
		if err == nil {
			if err := v.BindEnv(key, name); err != nil {
				return nil, false, fmt.Errorf("bind %s: %w", name, err)
			}
			return parsed, true, nil
		}
		switch action {
		case InvalidEnvironmentIgnore:
			return nil, false, nil
		case InvalidEnvironmentUsePartial:
			if !partial {
				return nil, false, nil
			}
			if err := v.BindEnv(key, name); err != nil {
				return nil, false, fmt.Errorf("bind %s: %w", name, err)
			}
			return parsed, true, nil
		default:
			return nil, false, fmt.Errorf("parse %s=%q: %w", name, value, err)
		}
	}
	return nil, false, nil
}

func parsedFlagValue(fieldType reflect.Type, flag *pflag.Flag) (any, error) {
	if indirectKind(fieldType) != reflect.Slice {
		value, _, err := parseScalarValue(fieldType, flag.Value.String())
		return value, err
	}

	sliceValue, ok := flag.Value.(pflag.SliceValue)
	if !ok {
		return nil, fmt.Errorf("flag is not a slice")
	}
	rawValues := sliceValue.GetSlice()
	result := reflect.MakeSlice(indirectType(fieldType), 0, len(rawValues))
	for _, rawValue := range rawValues {
		value, _, err := parseScalarValue(indirectType(fieldType).Elem(), rawValue)
		if err != nil {
			return nil, err
		}
		result = reflect.Append(result, reflect.ValueOf(value).Convert(result.Type().Elem()))
	}
	return result.Interface(), nil
}

func parseScalarValue(fieldType reflect.Type, value string) (any, bool, error) {
	targetType := indirectType(fieldType)
	if implements(targetType, textUnmarshalerType) {
		target := reflect.New(targetType)
		unmarshaler := target.Interface().(encoding.TextUnmarshaler)
		if err := unmarshaler.UnmarshalText([]byte(value)); err != nil {
			return target.Interface(), false, err
		}
		if fieldType.Kind() == reflect.Pointer {
			return target.Interface(), true, nil
		}
		return target.Elem().Interface(), true, nil
	}
	if targetType == reflect.TypeFor[time.Duration]() {
		parsed, err := time.ParseDuration(value)
		return parsed, true, err
	}

	switch targetType.Kind() {
	case reflect.String:
		return reflect.ValueOf(value).Convert(targetType).Interface(), true, nil
	case reflect.Bool:
		parsed, err := strconv.ParseBool(value)
		return parsed, true, err
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		parsed, err := strconv.ParseInt(value, 0, targetType.Bits())
		return reflect.ValueOf(parsed).Convert(targetType).Interface(), true, err
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		parsed, err := strconv.ParseUint(value, 10, targetType.Bits())
		return reflect.ValueOf(parsed).Convert(targetType).Interface(), true, err
	case reflect.Slice:
		return parseSliceValue(targetType, value)
	default:
		return value, true, nil
	}
}

func parseSliceValue(sliceType reflect.Type, value string) (any, bool, error) {
	switch sliceType.Elem().Kind() {
	case reflect.String:
		values, err := csv.NewReader(strings.NewReader(value)).Read()
		if err != nil {
			return nil, false, err
		}
		result := reflect.MakeSlice(sliceType, len(values), len(values))
		for i, item := range values {
			result.Index(i).Set(reflect.ValueOf(item).Convert(sliceType.Elem()))
		}
		return result.Interface(), true, nil
	case reflect.Int:
		rawValues := strings.Split(value, ",")
		result := reflect.MakeSlice(sliceType, len(rawValues), len(rawValues))
		for i, rawValue := range rawValues {
			parsed, err := strconv.Atoi(rawValue)
			if err != nil {
				return nil, false, err
			}
			result.Index(i).SetInt(int64(parsed))
		}
		return result.Interface(), true, nil
	default:
		return nil, false, fmt.Errorf("unsupported environment slice type %s", sliceType)
	}
}

func indirectType(configType reflect.Type) reflect.Type {
	for configType.Kind() == reflect.Pointer {
		configType = configType.Elem()
	}
	return configType
}

func indirectKind(configType reflect.Type) reflect.Kind {
	return indirectType(configType).Kind()
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
