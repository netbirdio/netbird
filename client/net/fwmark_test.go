package net

import (
	"testing"
)

func TestParseFwmarkBase(t *testing.T) {
	tests := []struct {
		name    string
		val     string
		want    uint32
		wantErr bool
	}{
		{name: "hex", val: "0x5A000", want: 0x5A000},
		{name: "hex upper case", val: "0X5A000", want: 0x5A000},
		{name: "decimal", val: "65536", want: 65536},
		{name: "octal", val: "0o400", want: 0o400},
		{name: "surrounding space", val: "  0x5A000 ", want: 0x5A000},
		{name: "highest usable base", val: "0xFFFFFF00", want: 0xFFFFFF00},
		{name: "low byte in use", val: "0x1BD01", wantErr: true},
		{name: "zero", val: "0", wantErr: true},
		{name: "not a number", val: "wireguard", wantErr: true},
		{name: "wider than 32 bit", val: "0x1FFFFFFFF", wantErr: true},
		{name: "negative", val: "-0x100", wantErr: true},
		{name: "empty", val: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseFwmarkBase(tc.val)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseFwmarkBase(%q) = %#x, want an error", tc.val, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFwmarkBase(%q): %v", tc.val, err)
			}
			if got != tc.want {
				t.Errorf("parseFwmarkBase(%q) = %#x, want %#x", tc.val, got, tc.want)
			}
		})
	}
}

// The marks have to stay inside the range the base defines, otherwise a host
// that moved the range to dodge a collision would still emit the old values.
func TestMarksStayWithinTheRange(t *testing.T) {
	lower, upper := fwmarkBase, fwmarkBase|fwmarkOffsetMask

	marks := map[string]uint32{
		"ControlPlaneMark":                 ControlPlaneMark,
		"DataPlaneMarkLower":               DataPlaneMarkLower,
		"DataPlaneMarkUpper":               DataPlaneMarkUpper,
		"DataPlaneMarkIn":                  DataPlaneMarkIn,
		"DataPlaneMarkOut":                 DataPlaneMarkOut,
		"PreroutingFwmarkRedirected":       PreroutingFwmarkRedirected,
		"PreroutingFwmarkMasquerade":       PreroutingFwmarkMasquerade,
		"PreroutingFwmarkMasqueradeReturn": PreroutingFwmarkMasqueradeReturn,
	}

	for name, mark := range marks {
		if mark < lower || mark > upper {
			t.Errorf("%s = %#x, outside the range %#x-%#x", name, mark, lower, upper)
		}
	}

	// the control plane mark must stay out of the data plane range, the netflow
	// conntrack path tells them apart by it
	if IsDataPlaneMark(ControlPlaneMark) {
		t.Errorf("ControlPlaneMark %#x is inside the data plane range", ControlPlaneMark)
	}
	for name, mark := range map[string]uint32{
		"DataPlaneMarkIn":                  DataPlaneMarkIn,
		"DataPlaneMarkOut":                 DataPlaneMarkOut,
		"PreroutingFwmarkRedirected":       PreroutingFwmarkRedirected,
		"PreroutingFwmarkMasquerade":       PreroutingFwmarkMasquerade,
		"PreroutingFwmarkMasqueradeReturn": PreroutingFwmarkMasqueradeReturn,
	} {
		if !IsDataPlaneMark(mark) {
			t.Errorf("%s = %#x is outside the data plane range %#x-%#x", name, mark, DataPlaneMarkLower, DataPlaneMarkUpper)
		}
	}
}

func TestDefaultMarksAreUnchanged(t *testing.T) {
	tests := map[string]struct {
		got  uint32
		want uint32
	}{
		"ControlPlaneMark":                 {ControlPlaneMark, 0x1BD00},
		"DataPlaneMarkLower":               {DataPlaneMarkLower, 0x1BD10},
		"DataPlaneMarkUpper":               {DataPlaneMarkUpper, 0x1BDFF},
		"DataPlaneMarkIn":                  {DataPlaneMarkIn, 0x1BD10},
		"DataPlaneMarkOut":                 {DataPlaneMarkOut, 0x1BD11},
		"PreroutingFwmarkRedirected":       {PreroutingFwmarkRedirected, 0x1BD20},
		"PreroutingFwmarkMasquerade":       {PreroutingFwmarkMasquerade, 0x1BD21},
		"PreroutingFwmarkMasqueradeReturn": {PreroutingFwmarkMasqueradeReturn, 0x1BD22},
	}

	if fwmarkBase != defaultFwmarkBase {
		t.Skipf("%s is set, the defaults do not apply", envFwmarkBase)
	}

	for name, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s = %#x, want %#x", name, tc.got, tc.want)
		}
	}
}
