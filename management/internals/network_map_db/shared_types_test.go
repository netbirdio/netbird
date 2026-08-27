package networkmapdb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRecordTypeAndRdata(t *testing.T) {
	var tests = []struct {
		recordType         string
		expectedRecordType int
		rdata              string
		expectedRdata      string
		expectedErr        error
	}{
		{recordType: "A", expectedRecordType: 1, rdata: "test.com", expectedRdata: "test.com", expectedErr: nil},
		{recordType: "AAAA", expectedRecordType: 28, rdata: "test.com", expectedRdata: "test.com", expectedErr: nil},
		{recordType: "CNAME", expectedRecordType: 5, rdata: "test.com", expectedRdata: "test.com.", expectedErr: nil},
		{recordType: "CNAME", expectedRecordType: 5, rdata: "test.com.", expectedRdata: "test.com.", expectedErr: nil},
		{recordType: "TypeMX", expectedErr: ErrDnsUnsupportedRecordType},
	}

	for _, tt := range tests {
		t.Run(tt.recordType, func(t *testing.T) {
			recordType, rdata, err := RecordTypeAndRdata(tt.recordType, tt.rdata)

			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, ErrDnsUnsupportedRecordType)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, recordType, tt.expectedRecordType)
			assert.Equal(t, rdata, tt.expectedRdata)
		})
	}
}
