package freebsd

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseIfconfigOutput(t *testing.T) {
	testOutput := `wg1: flags=8080<NOARP,MULTICAST> metric 0 mtu 1420
    options=80000<LINKSTATE>
    groups: wg
    nd6 options=109<PERFORMNUD,IFDISABLED,NO_DAD>`

	expected := &iface{
		Name:  "wg1",
		MTU:   1420,
		Group: "wg",
	}

	result, err := parseIfconfigOutput(testOutput)
	if err != nil {
		t.Errorf("Error parsing ifconfig output: %v", err)
		return
	}

	assert.Equal(t, expected.Name, result.Name, "Name should match")
	assert.Equal(t, expected.MTU, result.MTU, "MTU should match")
	assert.Equal(t, expected.Group, result.Group, "Group should match")
}

func TestParseIFName(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		expected    string
		expectedErr error
	}{
		{
			name:     "ValidOutput",
			output:   "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\ninet 192.168.0.10  netmask 255.255.255.0  broadcast 192.168.0.255",
			expected: "eth0",
		},
		{
			name:        "EmptyOutput",
			output:      "",
			expectedErr: fmt.Errorf("no output returned"),
		},
		{
			name:        "InvalidOutput",
			output:      "This is an invalid output",
			expectedErr: fmt.Errorf("invalid output"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := parseIFName(test.output)

			assert.Equal(t, test.expected, result, "Interface names should match")

			if test.expectedErr != nil {
				assert.NotNil(t, err, "Error should not be nil")
				assert.EqualError(t, err, test.expectedErr.Error(), "Error messages should match")
			} else {
				assert.Nil(t, err, "Error should be nil")
			}
		})
	}
}
