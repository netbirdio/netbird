package security

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"reflect"
	regexp
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Validator provides methods for validating various types of input
type Validator struct {
	// Logger for validation errors and warnings
	logger *logrus.Logger

	// Regular expressions for common validations
	regex struct {
		Email    *regexp.Regexp
		URL      *regexp.Regexp
		IP       *regexp.Regexp
		IPv4     *regexp.Regexp
		IPv6     *regexp.Regexp
		UUID     *regexp.Regexp
		HexColor *regexp.Regexp
		Alpha    *regexp.Regexp
		Numeric  *regexp.Regexp
		AlphaNum *regexp.Regexp
	}
}

// NewValidator creates a new Validator instance with default settings
func NewValidator() *Validator {
	v := &Validator{
		logger: logrus.StandardLogger(),
	}

	// Compile regular expressions
	v.regex.Email = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	v.regex.URL = regexp.MustCompile(`^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$`)
	v.regex.IP = regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$`)
	v.regex.IPv4 = regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)
	v.regex.IPv6 = regexp.MustCompile(`^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$`)
	v.regex.UUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	v.regex.HexColor = regexp.MustCompile(`^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)
	v.regex.Alpha = regexp.MustCompile(`^[a-zA-Z]+$`)
	v.regex.Numeric = regexp.MustCompile(`^[0-9]+$`)
	v.regex.AlphaNum = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

	return v
}

// ValidateStruct validates a struct based on its field tags
func (v *Validator) ValidateStruct(s interface{}) error {
	val := reflect.ValueOf(s)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return fmt.Errorf("expected a struct, got %T", s)
	}

	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// Skip unexported fields
		if !field.CanInterface() {
			continue
		}

		// Get field name from JSON tag if available
		fieldName := fieldType.Name
		if jsonTag := fieldType.Tag.Get("json"); jsonTag != "" {
			fieldName = strings.Split(jsonTag, ",")[0]
		}

		// Get validation rules from validate tag
		validateTag := fieldType.Tag.Get("validate")
		if validateTag == "" {
			continue
		}

		// Apply validation rules
		rules := strings.Split(validateTag, ",")
		for _, rule := range rules {
			rule = strings.TrimSpace(rule)
			if rule == "" {
				continue
			}

			// Parse rule and parameters
			var (
				ruleName string
				params   []string
			)

			if parts := strings.SplitN(rule, "=", 2); len(parts) == 2 {
				ruleName = strings.ToLower(parts[0])
				params = strings.Split(parts[1], "|")
			} else {
				ruleName = strings.ToLower(rule)
			}

			// Apply validation rule
			switch ruleName {
			case "required":
				if err := v.required(field, fieldName); err != nil {
					return err
				}
			case "email":
				if err := v.email(field, fieldName); err != nil {
					return err
				}
			case "url":
				if err := v.url(field, fieldName); err != nil {
					return err
				}
			case "ip":
				if err := v.ip(field, fieldName); err != nil {
					return err
				}
			case "ipv4":
				if err := v.ipv4(field, fieldName); err != nil {
					return err
				}
			case "ipv6":
				if err := v.ipv6(field, fieldName); err != nil {
					return err
				}
			case "uuid":
				if err := v.uuid(field, fieldName); err != nil {
					return err
				}
			case "hexcolor":
				if err := v.hexColor(field, fieldName); err != nil {
					return err
				}
			case "alpha":
				if err := v.alpha(field, fieldName); err != nil {
					return err
				}
			case "numeric":
				if err := v.numeric(field, fieldName); err != nil {
					return err
				}
			case "alphanum":
				if err := v.alphaNum(field, fieldName); err != nil {
					return err
				}
			case "min":
				if len(params) == 0 {
					return fmt.Errorf("missing parameter for 'min' validation on field %s", fieldName)
				}
				min, err := strconv.Atoi(params[0])
				if err != nil {
					return fmt.Errorf("invalid parameter for 'min' validation on field %s: %v", fieldName, err)
				}
				if err := v.min(field, fieldName, min); err != nil {
					return err
				}
			case "max":
				if len(params) == 0 {
					return fmt.Errorf("missing parameter for 'max' validation on field %s", fieldName)
				}
				max, err := strconv.Atoi(params[0])
				if err != nil {
					return fmt.Errorf("invalid parameter for 'max' validation on field %s: %v", fieldName, err)
				}
				if err := v.max(field, fieldName, max); err != nil {
					return err
				}
			case "len":
				if len(params) == 0 {
					return fmt.Errorf("missing parameter for 'len' validation on field %s", fieldName)
				}
				length, err := strconv.Atoi(params[0])
				if err != nil {
					return fmt.Errorf("invalid parameter for 'len' validation on field %s: %v", fieldName, err)
				}
				if err := v.length(field, fieldName, length); err != nil {
					return err
				}
			case "oneof":
				if len(params) == 0 {
					return fmt.Errorf("missing parameters for 'oneof' validation on field %s", fieldName)
				}
				if err := v.oneOf(field, fieldName, params); err != nil {
					return err
				}
			case "eqfield":
				if len(params) == 0 {
					return fmt.Errorf("missing parameter for 'eqfield' validation on field %s", fieldName)
				}
				otherFieldName := params[0]
				otherField, ok := typ.FieldByName(otherFieldName)
				if !ok {
					return fmt.Errorf("field %s not found for 'eqfield' validation on field %s", otherFieldName, fieldName)
				}
				if err := v.equalsField(field, val.FieldByName(otherFieldName), fieldName, otherFieldName); err != nil {
					return err
				}
			default:
				v.logger.Warnf("unknown validation rule '%s' on field %s", ruleName, fieldName)
			}
		}
	}

	return nil
}

// ValidateRequest validates an HTTP request based on the provided rules
func (v *Validator) ValidateRequest(r *http.Request, rules map[string]string) error {
	// Parse form data if not already parsed
	if r.Form == nil {
		if err := r.ParseForm(); err != nil {
			return fmt.Errorf("failed to parse form data: %v", err)
		}
	}

	// Validate each field based on the rules
	for field, rule := range rules {
		value := r.FormValue(field)
		if err := v.validateField(field, value, rule); err != nil {
			return err
		}
	}

	return nil
}

// validateField validates a single field based on the provided rules
func (v *Validator) validateField(field, value, rules string) error {
	if rules == "" {
		return nil
	}

	ruleList := strings.Split(rules, "|")
	for _, rule := range ruleList {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}

		// Parse rule and parameters
		var (
			ruleName string
			params   []string
		)

		if parts := strings.SplitN(rule, ":", 2); len(parts) == 2 {
			ruleName = strings.ToLower(strings.TrimSpace(parts[0]))
			params = strings.Split(parts[1], ",")
			// Trim whitespace from parameters
			for i := range params {
				params[i] = strings.TrimSpace(params[i])
			}
		} else {
			ruleName = strings.ToLower(strings.TrimSpace(rule))
		}

		// Apply validation rule
		switch ruleName {
		case "required":
			if value == "" {
				return fmt.Errorf("field %s is required", field)
			}
		case "email":
			if value != "" && !v.regex.Email.MatchString(value) {
				return fmt.Errorf("field %s must be a valid email address", field)
			}
		case "url":
			if value != "" && !v.regex.URL.MatchString(value) {
				return fmt.Errorf("field %s must be a valid URL", field)
			}
		case "ip":
			if value != "" && !v.regex.IP.MatchString(value) {
				return fmt.Errorf("field %s must be a valid IP address", field)
			}
		case "ipv4":
			if value != "" && !v.regex.IPv4.MatchString(value) {
				return fmt.Errorf("field %s must be a valid IPv4 address", field)
			}
		case "ipv6":
			if value != "" && !v.regex.IPv6.MatchString(value) {
				return fmt.Errorf("field %s must be a valid IPv6 address", field)
			}
		case "uuid":
			if value != "" && !v.regex.UUID.MatchString(value) {
				return fmt.Errorf("field %s must be a valid UUID", field)
			}
		case "hexcolor":
			if value != "" && !v.regex.HexColor.MatchString(value) {
				return fmt.Errorf("field %s must be a valid hex color code", field)
			}
		case "alpha":
			if value != "" && !v.regex.Alpha.MatchString(value) {
				return fmt.Errorf("field %s must contain only alphabetic characters", field)
			}
		case "numeric":
			if value != "" && !v.regex.Numeric.MatchString(value) {
				return fmt.Errorf("field %s must contain only numeric characters", field)
			}
		case "alphanum":
			if value != "" && !v.regex.AlphaNum.MatchString(value) {
				return fmt.Errorf("field %s must contain only alphanumeric characters", field)
			}
		case "min":
			if len(params) == 0 {
				return fmt.Errorf("missing parameter for 'min' validation on field %s", field)
			}
			min, err := strconv.Atoi(params[0])
			if err != nil {
				return fmt.Errorf("invalid parameter for 'min' validation on field %s: %v", field, err)
			}
			if len(value) < min {
				return fmt.Errorf("field %s must be at least %d characters long", field, min)
			}
		case "max":
			if len(params) == 0 {
				return fmt.Errorf("missing parameter for 'max' validation on field %s", field)
			}
			max, err := strconv.Atoi(params[0])
			if err != nil {
				return fmt.Errorf("invalid parameter for 'max' validation on field %s: %v", field, err)
			}
			if len(value) > max {
				return fmt.Errorf("field %s must be at most %d characters long", field, max)
			}
		case "len":
			if len(params) == 0 {
				return fmt.Errorf("missing parameter for 'len' validation on field %s", field)
			}
			length, err := strconv.Atoi(params[0])
			if err != nil {
				return fmt.Errorf("invalid parameter for 'len' validation on field %s: %v", field, err)
			}
			if len(value) != length {
				return fmt.Errorf("field %s must be exactly %d characters long", field, length)
			}
		case "oneof":
			if len(params) == 0 {
				return fmt.Errorf("missing parameters for 'oneof' validation on field %s", field)
			}
			found := false
			for _, param := range params {
				if value == param {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("field %s must be one of: %s", field, strings.Join(params, ", "))
			}
		case "eqfield":
			if len(params) == 0 {
				return fmt.Errorf("missing parameter for 'eqfield' validation on field %s", field)
			}
			otherField := params[0]
			otherValue := r.FormValue(otherField)
			if value != otherValue {
				return fmt.Errorf("field %s must be equal to field %s", field, otherField)
			}
		default:
			v.logger.Warnf("unknown validation rule '%s' on field %s", ruleName, field)
		}
	}

	return nil
}

// ValidateJSON validates a JSON request body against the provided struct
func (v *Validator) ValidateJSON(r *http.Request, dest interface{}) error {
	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %v", err)
	}

	// Restore the request body for potential further processing
	r.Body = io.NopCloser(strings.NewReader(string(body)))

	// Parse the JSON into the destination struct
	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("failed to parse JSON: %v", err)
	}

	// Validate the struct
	return v.ValidateStruct(dest)
}

// ValidateFile validates an uploaded file
func (v *Validator) ValidateFile(fileHeader *multipart.FileHeader, maxSize int64, allowedTypes []string) error {
	// Check file size
	if fileHeader.Size > maxSize {
		return fmt.Errorf("file size exceeds the maximum allowed size of %d bytes", maxSize)
	}

	// Check file type
	if len(allowedTypes) > 0 {
		contentType := fileHeader.Header.Get("Content-Type")
		allowed := false
		for _, t := range allowedTypes {
			if t == contentType {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("invalid file type: %s, allowed types: %v", contentType, allowedTypes)
		}
	}

	return nil
}

// ValidateTLSConfig validates a TLS configuration
func (v *Validator) ValidateTLSConfig(config *tls.Config) error {
	if config == nil {
		return fmt.Errorf("TLS configuration is required")
	}

	// Validate minimum TLS version
	if config.MinVersion < tls.VersionTLS12 {
		return fmt.Errorf("TLS version 1.2 or higher is required")
	}

	// Validate cipher suites
	if len(config.CipherSuites) == 0 {
		return fmt.Errorf("at least one cipher suite must be specified")
	}

	// Validate certificate
	if len(config.Certificates) == 0 && config.GetCertificate == nil && config.GetConfigForClient == nil {
		return fmt.Errorf("no certificate or certificate provider specified")
	}

	// Validate client authentication
	if config.ClientAuth == tls.RequireAndVerifyClientCert && config.ClientCAs == nil {
		return fmt.Errorf("client certificate verification is required but no CA pool is configured")
	}

	return nil
}

// ValidateCertificate validates an X.509 certificate
func (v *Validator) ValidateCertificate(cert *x509.Certificate, domain string, currentTime time.Time) error {
	// Check if the certificate is expired
	if currentTime.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not valid until %s", cert.NotBefore)
	}
	if currentTime.After(cert.NotAfter) {
		return fmt.Errorf("certificate expired on %s", cert.NotAfter)
	}

	// Check if the certificate is valid for the given domain
	if domain != "" {
		if err := cert.VerifyHostname(domain); err != nil {
			return fmt.Errorf("certificate is not valid for domain %s: %v", domain, err)
		}
	}

	// Check key usage
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("certificate cannot be used for digital signatures")
	}

	// Check extended key usage
	if len(cert.ExtKeyUsage) == 0 {
		return fmt.Errorf("no extended key usage specified")
	}

	return nil
}

// Helper methods for struct validation

func (v *Validator) required(field reflect.Value, fieldName string) error {
	if field.Interface() == reflect.Zero(field.Type()).Interface() {
		return fmt.Errorf("field %s is required", fieldName)
	}
	return nil
}

func (v *Validator) email(field reflect.Value, fieldName string) error {
	if field.Kind() != reflect.String {
		return fmt.Errorf("field %s must be a string", fieldName)
	}

	value := field.String()
	if value != "" && !v.regex.Email.MatchString(value) {
		return fmt.Errorf("field %s must be a valid email address", fieldName)
	}

	return nil
}

func (v *Validator) url(field reflect.Value, fieldName string) error {
	if field.Kind() != reflect.String {
		return fmt.Errorf("field %s must be a string", fieldName)
	}

	value := field.String()
	if value != "" && !v.regex.URL.MatchString(value) {
		return fmt.Errorf("field %s must be a valid URL", fieldName)
	}

	return nil
}

func (v *Validator) ip(field reflect.Value, fieldName string) error {
	if field.Kind() != reflect.String {
		return fmt.Errorf("field %s must be a string", fieldName)
	}

	value := field.String()
	if value != "" && !v.regex.IP.MatchString(value) {
		return fmt.Errorf("field %s must be a valid IP address", fieldName)
	}

	return nil
}

func (v *Validator) ipv4(field reflect.Value, fieldName string) error {
	if field.Kind() != reflect.String {
		return fmt.Errorf("field %s must be a string", fieldName)
	}

	value := field.String()
	if value != "" && !v.regex.IPv4.MatchString(value) {
		return fmt.Errorf("field %s must be a valid IPv4 address", fieldName)
	}

	return nil
}

func (v *Validator) ipv6(field reflect.Value, fieldName string) error {
	if field.Kind() != reflect.String {
		return fmt.Errorf("field %s must be a string", fieldName)
	}

	value := field.String()
	if value != "" && !v.regex.IPv6.MatchString(value) {
		return fmt.Errorf("field %s must be a valid IPv6 address", fieldName)
	}

	return nil
}

func (v *Validator) uuid(field reflect.Value, fieldName string) error {
	if field.Kind() != reflect.String {
		return fmt.Errorf("field %s must be a string", fieldName)
	}

	value := field.String()
	if value != "" && !v.regex.UUID.MatchString(value) {
		return fmt.Errorf("field %s must be a valid UUID", fieldName)
	}

	return nil
}

func (v *Validator) hexColor(field reflect.Value, fieldName string) error {
	if field.Kind() != reflect.String {
		return fmt.Errorf("field %s must be a string", fieldName)
	}

	value := field.String()
	if value != "" && !v.regex.HexColor.MatchString(value) {
		return fmt.Errorf("field %s must be a valid hex color code", fieldName)
	}

	return nil
}

func (v *Validator) alpha(field reflect.Value, fieldName string) error {
	if field.Kind() != reflect.String {
		return fmt.Errorf("field %s must be a string", fieldName)
	}

	value := field.String()
	if value != "" && !v.regex.Alpha.MatchString(value) {
		return fmt.Errorf("field %s must contain only alphabetic characters", fieldName)
	}

	return nil
}

func (v *Validator) numeric(field reflect.Value, fieldName string) error {
	if field.Kind() != reflect.String {
		return fmt.Errorf("field %s must be a string", fieldName)
	}

	value := field.String()
	if value != "" && !v.regex.Numeric.MatchString(value) {
		return fmt.Errorf("field %s must contain only numeric characters", fieldName)
	}

	return nil
}

func (v *Validator) alphaNum(field reflect.Value, fieldName string) error {
	if field.Kind() != reflect.String {
		return fmt.Errorf("field %s must be a string", fieldName)
	}

	value := field.String()
	if value != "" && !v.regex.AlphaNum.MatchString(value) {
		return fmt.Errorf("field %s must contain only alphanumeric characters", fieldName)
	}

	return nil
}

func (v *Validator) min(field reflect.Value, fieldName string, min int) error {
	switch field.Kind() {
	case reflect.String:
		if field.Len() < min {
			return fmt.Errorf("field %s must be at least %d characters long", fieldName, min)
		}
	case reflect.Slice, reflect.Array, reflect.Map:
		if field.Len() < min {
			return fmt.Errorf("field %s must have at least %d items", fieldName, min)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if field.Int() < int64(min) {
			return fmt.Errorf("field %s must be at least %d", fieldName, min)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if field.Uint() < uint64(min) {
			return fmt.Errorf("field %s must be at least %d", fieldName, min)
		}
	case reflect.Float32, reflect.Float64:
		if field.Float() < float64(min) {
			return fmt.Errorf("field %s must be at least %f", fieldName, float64(min))
		}
	default:
		return fmt.Errorf("field %s is not a string, slice, array, map, or number", fieldName)
	}

	return nil
}

func (v *Validator) max(field reflect.Value, fieldName string, max int) error {
	switch field.Kind() {
	case reflect.String:
		if field.Len() > max {
			return fmt.Errorf("field %s must be at most %d characters long", fieldName, max)
		}
	case reflect.Slice, reflect.Array, reflect.Map:
		if field.Len() > max {
			return fmt.Errorf("field %s must have at most %d items", fieldName, max)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if field.Int() > int64(max) {
			return fmt.Errorf("field %s must be at most %d", fieldName, max)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if field.Uint() > uint64(max) {
			return fmt.Errorf("field %s must be at most %d", fieldName, max)
		}
	case reflect.Float32, reflect.Float64:
		if field.Float() > float64(max) {
			return fmt.Errorf("field %s must be at most %f", fieldName, float64(max))
		}
	default:
		return fmt.Errorf("field %s is not a string, slice, array, map, or number", fieldName)
	}

	return nil
}

func (v *Validator) length(field reflect.Value, fieldName string, length int) error {
	switch field.Kind() {
	case reflect.String, reflect.Slice, reflect.Array, reflect.Map:
		if field.Len() != length {
			return fmt.Errorf("field %s must be exactly %d characters/items long", fieldName, length)
		}
	default:
		return fmt.Errorf("field %s is not a string, slice, array, or map", fieldName)
	}

	return nil
}

func (v *Validator) oneOf(field reflect.Value, fieldName string, values []string) error {
	if field.Kind() != reflect.String {
		return fmt.Errorf("field %s must be a string", fieldName)
	}

	value := field.String()
	found := false

	for _, v := range values {
		if value == v {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("field %s must be one of: %s", fieldName, strings.Join(values, ", "))
	}

	return nil
}

func (v *Validator) equalsField(field1, field2 reflect.Value, field1Name, field2Name string) error {
	if field1.Interface() != field2.Interface() {
		return fmt.Errorf("field %s must be equal to field %s", field1Name, field2Name)
	}
	return nil
}

// SanitizeInput removes potentially dangerous characters from the input string
func (v *Validator) SanitizeInput(input string) string {
	// Remove any HTML/script tags
	re := regexp.MustCompile(`<[^>]*>`)
	sanitized := re.ReplaceAllString(input, "")
	
	// Escape special characters
	sanitized = strings.ReplaceAll(sanitized, "\"", "&quot;")
	sanitized = strings.ReplaceAll(sanitized, "'", "&#39;")
	sanitized = strings.ReplaceAll(sanitized, "`", "&#96;")
	sanitized = strings.ReplaceAll(sanitized, "\\", "&#92;")
	
	return sanitized
}

// SanitizeURL ensures a URL is safe and well-formed
func (v *Validator) SanitizeURL(rawURL string) (string, error) {
	if rawURL == "" {
		return "", nil
	}

	// Parse the URL
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %v", err)
	}

	// Only allow http and https schemes
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid URL scheme: %s", u.Scheme)
	}

	// Reconstruct the URL with only allowed components
	sanitized := &url.URL{
		Scheme:   u.Scheme,
		User:     nil, // Remove user info
		Host:     u.Host,
		Path:     u.Path,
		RawQuery: u.Query().Encode(),
		Fragment: "", // Remove fragment
	}

	return sanitized.String(), nil
}
