package amneziawg

import (
	"os"
	"strconv"
)

const (
	envAmneziaJc   = "NETBIRD_AMNEZIA_JC"
	envAmneziaJmin = "NETBIRD_AMNEZIA_JMIN"
	envAmneziaJmax = "NETBIRD_AMNEZIA_JMAX"
	envAmneziaS1   = "NETBIRD_AMNEZIA_S1"
	envAmneziaS2   = "NETBIRD_AMNEZIA_S2"
	envAmneziaH1   = "NETBIRD_AMNEZIA_H1"
	envAmneziaH2   = "NETBIRD_AMNEZIA_H2"
	envAmneziaH3   = "NETBIRD_AMNEZIA_H3"
	envAmneziaH4   = "NETBIRD_AMNEZIA_H4"
	envAmneziaI1   = "NETBIRD_AMNEZIA_I1"
	envAmneziaI2   = "NETBIRD_AMNEZIA_I2"
	envAmneziaI3   = "NETBIRD_AMNEZIA_I3"
	envAmneziaI4   = "NETBIRD_AMNEZIA_I4"
	envAmneziaI5   = "NETBIRD_AMNEZIA_I5"
)

type StoreStruct struct {
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

var Store StoreStruct

func init() {

	Store = StoreStruct{
		Jc:   getAmneziaWgJc(),
		Jmin: getAmneziaWgJmin(),
		Jmax: getAmneziaWgJmax(),
		S1:   getAmneziaWgS1(),
		S2:   getAmneziaWgS2(),
		H1:   getAmneziaWgH1(),
		H2:   getAmneziaWgH2(),
		H3:   getAmneziaWgH3(),
		H4:   getAmneziaWgH4(),
		I1:   getAmneziaWgI1(),
		I2:   getAmneziaWgI2(),
		I3:   getAmneziaWgI3(),
		I4:   getAmneziaWgI4(),
		I5:   getAmneziaWgI5(),
	}
}

func getAmneziaWgJc() int32 {

	strval, ok := os.LookupEnv(envAmneziaJc)
	if !ok {
		return 0
	}
	val, err := strconv.ParseInt(strval, 10, 32)
	if err != nil {
		return 0
	}
	return int32(val)
}
func getAmneziaWgJmin() int32 {

	strval, ok := os.LookupEnv(envAmneziaJmin)
	if !ok {
		return 0
	}
	val, err := strconv.ParseInt(strval, 10, 32)
	if err != nil {
		return 0
	}
	return int32(val)
}
func getAmneziaWgJmax() int32 {

	strval, ok := os.LookupEnv(envAmneziaJmax)
	if !ok {
		return 0
	}
	val, err := strconv.ParseInt(strval, 10, 32)
	if err != nil {
		return 0
	}
	return int32(val)
}
func getAmneziaWgS1() int32 {

	strval, ok := os.LookupEnv(envAmneziaS1)
	if !ok {
		return 0
	}
	val, err := strconv.ParseInt(strval, 10, 32)
	if err != nil {
		return 0
	}
	return int32(val)
}
func getAmneziaWgS2() int32 {

	strval, ok := os.LookupEnv(envAmneziaS2)
	if !ok {
		return 0
	}
	val, err := strconv.ParseInt(strval, 10, 32)
	if err != nil {
		return 0
	}
	return int32(val)
}
func getAmneziaWgH1() uint32 {

	strval, ok := os.LookupEnv(envAmneziaH1)
	if !ok {
		return 0
	}
	val, err := strconv.ParseUint(strval, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(val)
}
func getAmneziaWgH2() uint32 {

	strval, ok := os.LookupEnv(envAmneziaH2)
	if !ok {
		return 0
	}
	val, err := strconv.ParseUint(strval, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(val)
}
func getAmneziaWgH3() uint32 {

	strval, ok := os.LookupEnv(envAmneziaH3)
	if !ok {
		return 0
	}
	val, err := strconv.ParseUint(strval, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(val)
}
func getAmneziaWgH4() uint32 {

	strval, ok := os.LookupEnv(envAmneziaH4)
	if !ok {
		return 0
	}
	val, err := strconv.ParseUint(strval, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(val)
}
func getAmneziaWgI1() string {

	val, ok := os.LookupEnv(envAmneziaI1)
	if !ok {
		return ""
	}
	return val
}
func getAmneziaWgI2() string {

	val, ok := os.LookupEnv(envAmneziaI2)
	if !ok {
		return ""
	}
	return val
}
func getAmneziaWgI3() string {

	val, ok := os.LookupEnv(envAmneziaI3)
	if !ok {
		return ""
	}
	return val
}
func getAmneziaWgI4() string {

	val, ok := os.LookupEnv(envAmneziaI4)
	if !ok {
		return ""
	}
	return val
}
func getAmneziaWgI5() string {

	val, ok := os.LookupEnv(envAmneziaI5)
	if !ok {
		return ""
	}
	return val
}
