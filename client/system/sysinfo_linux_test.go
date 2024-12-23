package system

import "testing"

func Test_sysInfo(t *testing.T) {
	tests := []struct {
		name             string
		sysInfo          SysInfo
		wantSerialNum    string
		wantProdName     string
		wantManufacturer string
	}{
		{
			name: "Test Case 1",
			sysInfo: SysInfo{
				ChassisSerial: "Default string",
				ProductSerial: "Default string",
				BoardSerial:   "M80-G8013200245",
				ProductName:   "B650M-HDV/M.2",
				BoardName:     "B650M-HDV/M.2",
				ProductVendor: "ASRock",
			},
			wantSerialNum:    "Default string",
			wantProdName:     "B650M-HDV/M.2",
			wantManufacturer: "ASRock",
		},
		{
			name: "Empty Chassis Serial",
			sysInfo: SysInfo{
				ChassisSerial: "",
				ProductSerial: "Default string",
				BoardSerial:   "M80-G8013200245",
				ProductName:   "B650M-HDV/M.2",
				BoardName:     "B650M-HDV/M.2",
				ProductVendor: "ASRock",
			},
			wantSerialNum:    "Default string",
			wantProdName:     "B650M-HDV/M.2",
			wantManufacturer: "ASRock",
		},
		{
			name: "Empty Chassis Serial",
			sysInfo: SysInfo{
				ChassisSerial: "",
				ProductSerial: "Default string",
				BoardSerial:   "M80-G8013200245",
				ProductName:   "B650M-HDV/M.2",
				BoardName:     "B650M-HDV/M.2",
				ProductVendor: "ASRock",
			},
			wantSerialNum:    "Default string",
			wantProdName:     "B650M-HDV/M.2",
			wantManufacturer: "ASRock",
		},
		{
			name: "Fallback to Product Serial",
			sysInfo: SysInfo{
				ChassisSerial: "Default string",
				ProductSerial: "Product serial",
				BoardSerial:   "M80-G8013200245",
				ProductName:   "B650M-HDV/M.2",
				BoardName:     "B650M-HDV/M.2",
				ProductVendor: "ASRock",
			},
			wantSerialNum:    "Product serial",
			wantProdName:     "B650M-HDV/M.2",
			wantManufacturer: "ASRock",
		},
		{
			name: "Fallback to Product Serial with default string",
			sysInfo: SysInfo{
				ChassisSerial: "Default string",
				ProductSerial: "Default string",
				BoardSerial:   "M80-G8013200245",
				ProductName:   "B650M-HDV/M.2",
				BoardName:     "B650M-HDV/M.2",
				ProductVendor: "ASRock",
			},
			wantSerialNum:    "Default string",
			wantProdName:     "B650M-HDV/M.2",
			wantManufacturer: "ASRock",
		},
		{
			name: "Non UTF-8 in Chassis Serial",
			sysInfo: SysInfo{
				ChassisSerial: "\x80",
				ProductSerial: "Product serial",
				BoardSerial:   "M80-G8013200245",
				ProductName:   "B650M-HDV/M.2",
				BoardName:     "B650M-HDV/M.2",
				ProductVendor: "ASRock",
			},
			wantSerialNum:    "Product serial",
			wantProdName:     "B650M-HDV/M.2",
			wantManufacturer: "ASRock",
		},
		{
			name: "Non UTF-8 in Chassis Serial and Product Serial",
			sysInfo: SysInfo{
				ChassisSerial: "\x80",
				ProductSerial: "\x80",
				BoardSerial:   "M80-G8013200245",
				ProductName:   "B650M-HDV/M.2",
				BoardName:     "B650M-HDV/M.2",
				ProductVendor: "ASRock",
			},
			wantSerialNum:    "M80-G8013200245",
			wantProdName:     "B650M-HDV/M.2",
			wantManufacturer: "ASRock",
		},
		{
			name: "Non UTF-8 in Chassis Serial and Product Serial and BoardSerial",
			sysInfo: SysInfo{
				ChassisSerial: "\x80",
				ProductSerial: "\x80",
				BoardSerial:   "\x80",
				ProductName:   "B650M-HDV/M.2",
				BoardName:     "B650M-HDV/M.2",
				ProductVendor: "ASRock",
			},
			wantSerialNum:    "",
			wantProdName:     "B650M-HDV/M.2",
			wantManufacturer: "ASRock",
		},

		{
			name: "Empty Product Name",
			sysInfo: SysInfo{
				ChassisSerial: "Default string",
				ProductSerial: "Default string",
				BoardSerial:   "M80-G8013200245",
				ProductName:   "",
				BoardName:     "boardname",
				ProductVendor: "ASRock",
			},
			wantSerialNum:    "Default string",
			wantProdName:     "boardname",
			wantManufacturer: "ASRock",
		},
		{
			name: "Invalid Product Name",
			sysInfo: SysInfo{
				ChassisSerial: "Default string",
				ProductSerial: "Default string",
				BoardSerial:   "M80-G8013200245",
				ProductName:   "\x80",
				BoardName:     "boardname",
				ProductVendor: "ASRock",
			},
			wantSerialNum:    "Default string",
			wantProdName:     "boardname",
			wantManufacturer: "ASRock",
		},
		{
			name: "Invalid BoardName Name",
			sysInfo: SysInfo{
				ChassisSerial: "Default string",
				ProductSerial: "Default string",
				BoardSerial:   "M80-G8013200245",
				ProductName:   "\x80",
				BoardName:     "\x80",
				ProductVendor: "ASRock",
			},
			wantSerialNum:    "Default string",
			wantProdName:     "",
			wantManufacturer: "ASRock",
		},
		{
			name: "Invalid chars",
			sysInfo: SysInfo{
				ChassisSerial: "\x80",
				ProductSerial: "\x80",
				BoardSerial:   "\x80",
				ProductName:   "\x80",
				BoardName:     "\x80",
				ProductVendor: "\x80",
			},
			wantSerialNum:    "",
			wantProdName:     "",
			wantManufacturer: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getSystemInfo = func() SysInfo {
				return tt.sysInfo
			}
			gotSerialNum, gotProdName, gotManufacturer := sysInfo()
			if gotSerialNum != tt.wantSerialNum {
				t.Errorf("sysInfo() gotSerialNum = %v, want %v", gotSerialNum, tt.wantSerialNum)
			}
			if gotProdName != tt.wantProdName {
				t.Errorf("sysInfo() gotProdName = %v, want %v", gotProdName, tt.wantProdName)
			}
			if gotManufacturer != tt.wantManufacturer {
				t.Errorf("sysInfo() gotManufacturer = %v, want %v", gotManufacturer, tt.wantManufacturer)
			}
		})
	}
}
