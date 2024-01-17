package system

const (
	ChassisTypeOther               uint = 0x01 // Other
	ChassisTypeUnknown             uint = 0x02 // Unknown
	ChassisTypeDesktop             uint = 0x03 // Desktop
	ChassisTypeLowProfileDesktop   uint = 0x04 // Low Profile Desktop
	ChassisTypePizzaBox            uint = 0x05 // Pizza Box
	ChassisTypeMiniTower           uint = 0x06 // Mini Tower
	ChassisTypeTower               uint = 0x07 // Tower
	ChassisTypePortable            uint = 0x08 // Portable
	ChassisTypeLaptop              uint = 0x09 // Laptop
	ChassisTypeNotebook            uint = 0x0a // Notebook
	ChassisTypeHandHeld            uint = 0x0b // Hand Held
	ChassisTypeDockingStation      uint = 0x0c // Docking Station
	ChassisTypeAllInOne            uint = 0x0d // All in One
	ChassisTypeSubNotebook         uint = 0x0e // Sub Notebook
	ChassisTypeSpacesaving         uint = 0x0f // Space-saving
	ChassisTypeLunchBox            uint = 0x10 // Lunch Box
	ChassisTypeMainServerChassis   uint = 0x11 // Main Server Chassis
	ChassisTypeExpansionChassis    uint = 0x12 // Expansion Chassis
	ChassisTypeSubChassis          uint = 0x13 // SubChassis
	ChassisTypeBusExpansionChassis uint = 0x14 // Bus Expansion Chassis
	ChassisTypePeripheralChassis   uint = 0x15 // Peripheral Chassis
	ChassisTypeRAIDChassis         uint = 0x16 // RAID Chassis
	ChassisTypeRackMountChassis    uint = 0x17 // Rack Mount Chassis
	ChassisTypeSealedcasePC        uint = 0x18 // Sealed-case PC
	ChassisTypeMultisystemChassis  uint = 0x19 // Multi-system chassis
	ChassisTypeCompactPCI          uint = 0x1a // Compact PCI
	ChassisTypeAdvancedTCA         uint = 0x1b // Advanced TCA
	ChassisTypeBlade               uint = 0x1c // Blade
	ChassisTypeBladeChassis        uint = 0x1d // Blade Chassis
	ChassisTypeTablet              uint = 0x1e // Tablet
	ChassisTypeConvertible         uint = 0x1f // Convertible
	ChassisTypeDetachable          uint = 0x20 // Detachable
	ChassisTypeIoTGateway          uint = 0x21 // IoT Gateway
	ChassisTypeEmbeddedPC          uint = 0x22 // Embedded PC
	ChassisTypeMiniPC              uint = 0x23 // Mini PC
	ChassisTypeStickPC             uint = 0x24 // Stick PC
)

func chassisTypeDesc(id uint) string {
	switch id {
	case ChassisTypeOther:
		return "Other"
	case ChassisTypeUnknown:
		return "Unknown"
	case ChassisTypeDesktop:
		return "Desktop"
	case ChassisTypeLowProfileDesktop:
		return "Low Profile Desktop"
	case ChassisTypePizzaBox:
		return "Pizza Box"
	case ChassisTypeMiniTower:
		return "Mini Tower"
	case ChassisTypeTower:
		return "Tower"
	case ChassisTypePortable:
		return "Portable"
	case ChassisTypeLaptop:
		return "Laptop"
	case ChassisTypeNotebook:
		return "Notebook"
	case ChassisTypeHandHeld:
		return "Hand Held"
	case ChassisTypeDockingStation:
		return "Docking Station"
	case ChassisTypeAllInOne:
		return "All In One"
	case ChassisTypeSubNotebook:
		return "Sub Notebook"
	case ChassisTypeSpacesaving:
		return "Space-saving"
	case ChassisTypeLunchBox:
		return "Lunch Box"
	case ChassisTypeMainServerChassis:
		return "Main Server Chassis"
	case ChassisTypeExpansionChassis:
		return "Expansion Chassis"
	case ChassisTypeSubChassis:
		return "Sub Chassis"
	case ChassisTypeBusExpansionChassis:
		return "Bus Expansion Chassis"
	case ChassisTypePeripheralChassis:
		return "Peripheral Chassis"
	case ChassisTypeRAIDChassis:
		return "RAID Chassis"
	case ChassisTypeRackMountChassis:
		return "Rack Mount Chassis"
	case ChassisTypeSealedcasePC:
		return "Sealed-case PC"
	case ChassisTypeMultisystemChassis:
		return "Multi-system"
	case ChassisTypeCompactPCI:
		return "CompactPCI"
	case ChassisTypeAdvancedTCA:
		return "AdvancedTCA"
	case ChassisTypeBlade:
		return "Blade"
	case ChassisTypeBladeChassis:
		return "Blade Chassis"
	case ChassisTypeTablet:
		return "Tablet"
	case ChassisTypeConvertible:
		return "Convertible"
	case ChassisTypeDetachable:
		return "Detachable"
	case ChassisTypeIoTGateway:
		return "IoT Gateway"
	case ChassisTypeEmbeddedPC:
		return "Embedded PC"
	case ChassisTypeMiniPC:
		return "Mini PC"
	case ChassisTypeStickPC:
		return "Stick PC"
	default:
		return "Unknown"
	}
}
