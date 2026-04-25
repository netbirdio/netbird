package entra_device

import "encoding/asn1"

// realASN1Unmarshal is the real call into encoding/asn1, wrapped behind a
// package-level function variable so unit tests can substitute it.
func realASN1Unmarshal(data []byte, dst any) ([]byte, error) {
	return asn1.Unmarshal(data, dst)
}
