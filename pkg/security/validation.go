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

// Validator provides comprehensive input validation and sanitization capabilities.
// It supports validation of various data types including emails, URLs, IPs, UUIDs,
// and custom validation rules. The validator uses pre-compiled regular expressions
// for efficient validation.
//
// Example usage:
//
//	validator := NewValidator()
//	err := validator.ValidateStruct(myStruct)
//	if err != nil {
//		// Handle validation error
//	}
//
// Thread-safety: The Validator is safe for concurrent use after initialization.
type Validator struct {
	// logger is used for logging validation errors and warnings
	logger *logrus.Logger

	// regex contains pre-compiled regular expressions for common validations
	regex struct {
		Email    *regexp.Regexp // Email address validation
		URL      *regexp.Regexp // URL validation
		IP       *regexp.Regexp // IP address (IPv4 or IPv6) validation
		IPv4     *regexp.Regexp // IPv4 address validation
		IPv6     *regexp.Regexp // IPv6 address validation
		UUID     *regexp.Regexp // UUID validation
		HexColor *regexp.Regexp // Hexadecimal color code validation
		Alpha    *regexp.Regexp // Alphabetic characters only
		Numeric  *regexp.Regexp // Numeric characters only
		AlphaNum *regexp.Regexp // Alphanumeric characters only
	}
}

// NewValidator creates a new Validator instance with default settings.
// The validator is initialized with pre-compiled regular expressions for
// common validation patterns.
//
// Returns a configured Validator ready to use.
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

// ValidateStruct validates a struct based on validation tags in its fields.
// The function uses reflection to inspect struct fields and apply validation
// rules specified in the "validate" tag.
//
// Supported validation rules:
//   - required: Field must not be empty
//   - email: Field must be a valid email address
//   - url: Field must be a valid URL
//   - ip/ipv4/ipv6: Field must be a valid IP address
//   - uuid: Field must be a valid UUID
//   - min=N: Field must have minimum length/value of N
//   - max=N: Field must have maximum length/value of N
//   - len=N: Field must have exact length/value of N
//   - oneof=val1,val2,...: Field must be one of the specified values
//   - eqfield=fieldName: Field must equal another field in the struct
//
// Example struct:
//
//	type User struct {
//		Email string `validate:"required,email"`
//		Age   int    `validate:"min=18,max=120"`
//	}
//
// Parameters:
//   - s: The struct to validate (can be a pointer or value)
//
// Returns:
//   - nil if all validations pass
//   - An error describing the first validation failure
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

// ValidateRequest validates form data from an HTTP request based on provided rules.
// The function parses the form data (if not already parsed) and validates each
// field according to the rules map.
//
// Rules format: "rule1|rule2:param1,param2|rule3"
// Example: "required|email|min:10|max:100"
//
// Parameters:
//   - r: The HTTP request containing form data
//   - rules: A map of field names to validation rules
//
// Returns:
//   - nil if all validations pass
//   - An error describing the first validation failure
//
// Note: This function handles eqfield validation separately as it requires
// access to other fields in the request.
func (v *Validator) ValidateRequest(r *http.Request, rules map[string]string) error {
	// Parse form data if not already parsed
	if r.Form == nil {
		if err := r.ParseForm(); err != nil {
			return fmt.Errorf("failed to parse form data: %v", err)
		}
	}

	// First pass: validate eqfield rules that depend on other fields
	for field, rule := range rules {
		value := r.FormValue(field)
		if err := v.validateFieldWithRequest(field, value, rule, r); err != nil {
			return err
		}
	}

	// Second pass: validate all other rules
	for field, rule := range rules {
		value := r.FormValue(field)
		if err := v.validateField(field, value, rule); err != nil {
			return err
		}
	}

	return nil
}

// validateField validates a single field value against a set of validation rules.
// This is an internal helper function used by ValidateRequest.
//
// Parameters:
//   - field: The field name (for error messages)
//   - value: The field value to validate
//   - rules: The validation rules to apply (pipe-separated)
//
// Returns:
//   - nil if all validations pass
//   - An error describing the first validation failure
//
// Note: eqfield validation is skipped here and handled separately in
// validateFieldWithRequest as it requires access to the request.
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
			// eqfield validation requires request context, skip here
			// It will be handled in validateFieldWithRequest
			continue
		default:
			v.logger.Warnf("unknown validation rule '%s' on field %s", ruleName, field)
		}
	}

	return nil
}

// validateFieldWithRequest validates a single field with access to the HTTP request.
// This is used for validation rules that need to access other fields from the request,
// such as eqfield (field equality) validation.
//
// Parameters:
//   - field: The field name (for error messages)
//   - value: The field value to validate
//   - rules: The validation rules to apply
//   - r: The HTTP request containing form data
//
// Returns:
//   - nil if all validations pass
//   - An error describing the first validation failure
func (v *Validator) validateFieldWithRequest(field, value, rules string, r *http.Request) error {
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

		// Apply validation rule that requires request context
		switch ruleName {
		case "eqfield":
			if len(params) == 0 {
				return fmt.Errorf("missing parameter for 'eqfield' validation on field %s", field)
			}
			otherField := params[0]
			otherValue := r.FormValue(otherField)
			if value != otherValue {
				return fmt.Errorf("field %s must be equal to field %s", field, otherField)
			}
		}
	}

	return nil
}

// ValidateJSON validates a JSON request body against the provided struct.
// The function reads the request body, unmarshals it into the destination struct,
// and then validates the struct using ValidateStruct.
//
// Security: This function enforces a maximum request body size (10MB) to prevent
// DoS attacks through large request bodies. The request body is restored after
// reading, so it can be read again if needed.
//
// Parameters:
//   - r: The HTTP request containing JSON data
//   - dest: A pointer to the struct to unmarshal and validate
//
// Returns:
//   - nil if JSON parsing and validation succeed
//   - An error if JSON parsing fails, validation fails, or body size exceeds limit
//
// Example:
//
//	type User struct {
//		Email string `validate:"required,email"`
//		Name  string `validate:"required,min=3"`
//	}
//
//	var user User
//	if err := validator.ValidateJSON(r, &user); err != nil {
//		// Handle error
//	}
func (v *Validator) ValidateJSON(r *http.Request, dest interface{}) error {
	// Security: Limit request body size to prevent DoS attacks
	// 10MB is a reasonable limit for most JSON API requests
	const maxRequestBodySize = 10 * 1024 * 1024 // 10MB
	
	// Limit the request body size to prevent DoS attacks
	limitedReader := io.LimitReader(r.Body, maxRequestBodySize+1)
	
	// Read the request body with size limit
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("failed to read request body: %v", err)
	}
	
	// Check if body exceeded the size limit
	if len(body) > maxRequestBodySize {
		return fmt.Errorf("request body too large: maximum size is %d bytes", maxRequestBodySize)
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

// ValidateFile validates an uploaded file to ensure it meets size and type requirements.
// This helps prevent security issues like file upload attacks and resource exhaustion.
//
// Parameters:
//   - fileHeader: The multipart file header from the request
//   - maxSize: Maximum allowed file size in bytes
//   - allowedTypes: List of allowed MIME types (empty slice = all types allowed)
//
// Returns:
//   - nil if the file is valid
//   - An error if the file exceeds size limit or has an invalid type
//
// Security: This function helps prevent:
//   - File upload attacks (malicious files)
//   - Resource exhaustion (large files)
//   - Type confusion attacks (wrong file types)
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

// ValidateTLSConfig validates a TLS configuration to ensure it meets security requirements.
// This helps prevent insecure TLS configurations that could lead to security vulnerabilities.
//
// Parameters:
//   - config: The TLS configuration to validate
//
// Returns:
//   - nil if the configuration is valid
//   - An error if the configuration is invalid or insecure
//
// Validation checks:
//   - Minimum TLS version is 1.2 or higher
//   - At least one cipher suite is specified
//   - Certificate or certificate provider is configured
//   - Client certificate verification is properly configured (if required)
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

// ValidateCertificate validates an X.509 certificate to ensure it is valid and
// appropriate for use. This helps prevent security issues from expired or
// invalid certificates.
//
// Parameters:
//   - cert: The X.509 certificate to validate
//   - domain: The domain name the certificate should be valid for (optional)
//   - currentTime: The current time for expiration checks
//
// Returns:
//   - nil if the certificate is valid
//   - An error if the certificate is expired, not yet valid, invalid for the domain,
//     or missing required key usage
//
// Validation checks:
//   - Certificate is not expired
//   - Certificate is not valid yet (not before check)
//   - Certificate is valid for the specified domain (if provided)
//   - Certificate has digital signature key usage
//   - Certificate has extended key usage specified
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
// to prevent XSS (Cross-Site Scripting) attacks. This function provides basic
// XSS protection by removing HTML/script tags and escaping special characters.
//
// Parameters:
//   - input: The string to sanitize
//
// Returns:
//   - A sanitized string safe for display in HTML contexts
//
// Security features:
//   - Removes HTML and script tags
//   - Removes script and style tag contents
//   - Removes javascript: and data: URLs
//   - Escapes HTML entities (&, <, >, ", ', `, \)
//   - Removes null bytes and control characters
//
// Note: This provides basic protection. For production use, consider using
// a dedicated HTML sanitization library for more comprehensive protection.
func (v *Validator) SanitizeInput(input string) string {
	if input == "" {
		return input
	}

	// Remove any HTML/script tags and their content
	// This regex matches < followed by any characters until >
	htmlTagRegex := regexp.MustCompile(`<[^>]*>`)
	sanitized := htmlTagRegex.ReplaceAllString(input, "")
	
	// Remove script and style tags with their content (more comprehensive)
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	sanitized = scriptRegex.ReplaceAllString(sanitized, "")
	
	styleRegex := regexp.MustCompile(`(?i)<style[^>]*>.*?</style>`)
	sanitized = styleRegex.ReplaceAllString(sanitized, "")
	
	// Remove javascript: and data: URLs
	jsUrlRegex := regexp.MustCompile(`(?i)javascript:`)
	sanitized = jsUrlRegex.ReplaceAllString(sanitized, "")
	
	dataUrlRegex := regexp.MustCompile(`(?i)data:`)
	sanitized = dataUrlRegex.ReplaceAllString(sanitized, "")
	
	// Escape special characters to prevent XSS
	sanitized = strings.ReplaceAll(sanitized, "&", "&amp;")
	sanitized = strings.ReplaceAll(sanitized, "<", "&lt;")
	sanitized = strings.ReplaceAll(sanitized, ">", "&gt;")
	sanitized = strings.ReplaceAll(sanitized, "\"", "&quot;")
	sanitized = strings.ReplaceAll(sanitized, "'", "&#39;")
	sanitized = strings.ReplaceAll(sanitized, "`", "&#96;")
	sanitized = strings.ReplaceAll(sanitized, "\\", "&#92;")
	
	// Remove null bytes and control characters
	nullByteRegex := regexp.MustCompile(`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`)
	sanitized = nullByteRegex.ReplaceAllString(sanitized, "")
	
	return sanitized
}

// SanitizeURL ensures a URL is safe and well-formed by validating and sanitizing it.
// This helps prevent security issues like open redirect attacks and protocol confusion.
//
// Parameters:
//   - rawURL: The raw URL string to sanitize
//
// Returns:
//   - A sanitized URL string if valid
//   - An error if the URL is invalid or uses an unsafe scheme
//
// Security features:
//   - Only allows http and https schemes
//   - Removes user info (username/password) from URL
//   - Removes fragment (#) from URL
//   - Validates URL format
//
// Note: This function helps prevent open redirect attacks by only allowing
// safe URL schemes. User info and fragments are removed for security.
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
