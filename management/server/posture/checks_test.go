package posture

import (
	"encoding/json"
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
				Checks: ChecksDefinition{
					NBVersionCheck: &NBVersionCheck{
						MinVersion: "1.0.0",
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
                            "MinVersion": "1.0.0"
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
				Checks: ChecksDefinition{
					NBVersionCheck: &NBVersionCheck{},
				},
			},
			want: []byte(`
				{
					"ID": "",
                    "Name": "",
                    "Description": "",
                    "Checks": {
                        "NBVersionCheck": {
                            "MinVersion": ""
                        }
                    }
                }
			`),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.checks)
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
                            "MinVersion": "1.0.0"
                        }
                    }
                }
			`),
			expected: &Checks{
				ID:          "id1",
				Name:        "name1",
				Description: "desc1",
				Checks: ChecksDefinition{
					NBVersionCheck: &NBVersionCheck{
						MinVersion: "1.0.0",
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
			name:          "Empty JSON Posture Check Unmarshal",
			in:            []byte(`{}`),
			expected:      &Checks{},
			expectedError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			var checks Checks
			err := json.Unmarshal(tc.in, &checks)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, &checks)
			}
		})
	}
}

func TestChecks_Validate(t *testing.T) {
	testCases := []struct {
		name          string
		checks        Checks
		expectedError bool
	}{
		{
			name: "Valid checks version",
			checks: Checks{
				Checks: ChecksDefinition{
					NBVersionCheck: &NBVersionCheck{
						MinVersion: "0.25.0",
					},
					OSVersionCheck: &OSVersionCheck{
						Ios: &MinVersionCheck{
							MinVersion: "13.0.1",
						},
						Linux: &MinKernelVersionCheck{
							MinKernelVersion: "5.3.3-dev",
						},
					},
				},
			},
			expectedError: false,
		},
		{
			name: "Invalid checks version",
			checks: Checks{
				Checks: ChecksDefinition{
					NBVersionCheck: &NBVersionCheck{
						MinVersion: "abc",
					},
					OSVersionCheck: &OSVersionCheck{
						Android: &MinVersionCheck{
							MinVersion: "dev",
						},
					},
				},
			},
			expectedError: true,
		},
		{
			name: "Combined valid and invalid checks version",
			checks: Checks{
				Checks: ChecksDefinition{
					NBVersionCheck: &NBVersionCheck{
						MinVersion: "abc",
					},
					OSVersionCheck: &OSVersionCheck{
						Windows: &MinKernelVersionCheck{
							MinKernelVersion: "10.0.1234",
						},
						Darwin: &MinVersionCheck{
							MinVersion: "13.0.1",
						},
					},
				},
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.checks.Validate()
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
