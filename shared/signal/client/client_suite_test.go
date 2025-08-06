package client

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestSignal(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Signal Suite")
}
