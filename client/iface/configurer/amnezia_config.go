package configurer

// AmneziaConfig describes AmneziaWG obfuscation parameters.
// If nil or all fields are zero, it behaves as standard WireGuard.
type AmneziaConfig interface {
	IsEmpty() bool
	GetJc() int32
	GetJmin() int32
	GetJmax() int32
	GetS1() int32
	GetS2() int32
	GetH1() uint32
	GetH2() uint32
	GetH3() uint32
	GetH4() uint32
	GetI1() string
	GetI2() string
	GetI3() string
	GetI4() string
	GetI5() string
}
