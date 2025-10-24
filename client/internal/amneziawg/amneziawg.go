package amneziawg

// AmneziaConfig describes AmneziaWG obfuscation parameters.
// If nil or all fields are zero, it behaves as standard WireGuard.
type AmneziaConfig struct {
	Jc   int32
	Jmin int32
	Jmax int32
	S1   int32
	S2   int32
	H1   uint32
	H2   uint32
	H3   uint32
	H4   uint32
	I1   string
	I2   string
	I3   string
	I4   string
	I5   string
}

func (cfg AmneziaConfig) IsEmpty() bool {

	return cfg.Jc == 0 && cfg.Jmin == 0 && cfg.Jmax == 0 &&
		cfg.S1 == 0 && cfg.S2 == 0 &&
		cfg.H1 == 0 && cfg.H2 == 0 && cfg.H3 == 0 && cfg.H4 == 0 &&
		cfg.I1 == "" && cfg.I2 == "" && cfg.I3 == "" && cfg.I4 == "" && cfg.I5 == ""
}
func (cfg AmneziaConfig) GetJc() int32   { return cfg.Jc }
func (cfg AmneziaConfig) GetJmin() int32 { return cfg.Jmin }
func (cfg AmneziaConfig) GetJmax() int32 { return cfg.Jmax }
func (cfg AmneziaConfig) GetS1() int32   { return cfg.S1 }
func (cfg AmneziaConfig) GetS2() int32   { return cfg.S2 }
func (cfg AmneziaConfig) GetH1() uint32  { return cfg.H1 }
func (cfg AmneziaConfig) GetH2() uint32  { return cfg.H2 }
func (cfg AmneziaConfig) GetH3() uint32  { return cfg.H3 }
func (cfg AmneziaConfig) GetH4() uint32  { return cfg.H4 }
func (cfg AmneziaConfig) GetI1() string  { return cfg.I1 }
func (cfg AmneziaConfig) GetI2() string  { return cfg.I2 }
func (cfg AmneziaConfig) GetI3() string  { return cfg.I3 }
func (cfg AmneziaConfig) GetI4() string  { return cfg.I4 }
func (cfg AmneziaConfig) GetI5() string  { return cfg.I5 }
