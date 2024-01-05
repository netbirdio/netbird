package posture

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChecks_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		checks  *Checks
		want    []byte
		wantErr bool
	}{
		{
			name: "Valid Posture Checks Marshal",
			checks: &Checks{
				ID:          "id1",
				Name:        "name1",
				Description: "desc1",
				AccountID:   "acc1",
				Checks: []Check{
					&NBVersionCheck{
						Enabled:    true,
						MinVersion: "1.0.0",
						MaxVersion: "1.2.9",
					},
				},
			},
			want: []byte(`
				{
					"ID": "id1",
                    "Name": "name1",
                    "Description": "desc1",
                    "Checks": {
                        "NBVersionCheck": {
                            "Enabled": true,
                            "MinVersion": "1.0.0",
                            "MaxVersion": "1.2.9"
                        }
                    }
                }
			`),
			wantErr: false,
		},
		{
			name: "Empty Posture Checks Marshal",
			checks: &Checks{
				ID:          "",
				Name:        "",
				Description: "",
				AccountID:   "",
				Checks: []Check{
					&NBVersionCheck{},
				},
			},
			want: []byte(`
				{
					"ID": "",
                    "Name": "",
                    "Description": "",
                    "Checks": {
                        "NBVersionCheck": {
                            "Enabled": false,
                            "MinVersion": "",
                            "MaxVersion": ""
                        }
                    }
                }
			`),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.checks.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("Checks.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.JSONEq(t, string(got), string(tt.want))
			assert.Equal(t, tt.checks, tt.checks.Copy(), "original Checks should not be modified")
		})
	}
}

func TestChecks_UnmarshalJSON(t *testing.T) {
	testCases := []struct {
		name          string
		in            []byte
		expected      *Checks
		expectedError bool
	}{
		{
			name: "Valid JSON Posture Checks Unmarshal",
			in: []byte(`
				{
					"ID": "id1",
                    "Name": "name1",
                    "Description": "desc1",
                    "Checks": {
                        "NBVersionCheck": {
                            "Enabled": true,
                            "MinVersion": "1.0.0",
                            "MaxVersion": "1.2.9"
                        }
                    }
                }
			`),
			expected: &Checks{
				ID:          "id1",
				Name:        "name1",
				Description: "desc1",
				Checks: []Check{
					&NBVersionCheck{
						Enabled:    true,
						MinVersion: "1.0.0",
						MaxVersion: "1.2.9",
					},
				},
			},
			expectedError: false,
		},
		{
			name:          "Invalid JSON Posture Checks Unmarshal",
			in:            []byte(`{`),
			expectedError: true,
		},
		{
			name: "Empty JSON Posture Check Unmarshal",
			in:   []byte(`{}`),
			expected: &Checks{
				Checks: make([]Check, 0),
			},
			expectedError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			checks := &Checks{}

			err := checks.UnmarshalJSON(tc.in)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, checks)
			}
		})
	}
}
