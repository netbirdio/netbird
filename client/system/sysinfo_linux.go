package system

// SysInfo used to moc out the sysinfo getter
type SysInfo struct {
	ChassisSerial string
	ProductSerial string
	BoardSerial   string

	ProductName   string
	BoardName     string
	ProductVendor string
}
