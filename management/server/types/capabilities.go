package types

// Server capability advertisement strings sent in ServerKeyResponse.
// Clients check these before attempting enrollment or presenting device certificates.
// Using string constants (not proto enums) keeps forward compatibility:
// unknown capability strings are safely ignored by old clients.
const (
	// CapabilityDeviceCertAuth indicates the server supports device certificate authentication.
	CapabilityDeviceCertAuth = "DEVICE_CERT_AUTH"

	// CapabilityDeviceAttestation indicates the server supports TPM EK attestation (Mode C enrollment).
	CapabilityDeviceAttestation = "DEVICE_ATTESTATION"
)
