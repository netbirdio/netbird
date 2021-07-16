package util_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/wiretrustee/wiretrustee/util"
	"io/ioutil"
)

var _ = Describe("Client", func() {

	type TestConfig struct {
		SomeMap   map[string]string
		SomeArray []string
		SomeField int
	}

	Describe("Config", func() {
		Context("in JSON format", func() {
			It("should be written and read successfully", func() {

				tmpDir, err := ioutil.TempDir("", "wiretrustee_util_test_tmp_*")
				Expect(err).NotTo(HaveOccurred())

				m := make(map[string]string)
				m["key1"] = "value1"
				m["key2"] = "value2"

				arr := []string{"value1", "value2"}

				written := &TestConfig{
					SomeMap:   m,
					SomeArray: arr,
					SomeField: 99,
				}

				err = util.WriteJson(tmpDir+"/testconfig.json", written)
				Expect(err).NotTo(HaveOccurred())

				read, err := util.ReadJson(tmpDir+"/testconfig.json", &TestConfig{})
				Expect(err).NotTo(HaveOccurred())
				Expect(read).NotTo(BeNil())
				Expect(read.(*TestConfig).SomeMap["key1"]).To(BeEquivalentTo(written.SomeMap["key1"]))
				Expect(read.(*TestConfig).SomeMap["key2"]).To(BeEquivalentTo(written.SomeMap["key2"]))
				Expect(read.(*TestConfig).SomeArray[0]).To(BeEquivalentTo(written.SomeArray[0]))
				Expect(read.(*TestConfig).SomeArray[1]).To(BeEquivalentTo(written.SomeArray[1]))
				Expect(read.(*TestConfig).SomeField).To(BeEquivalentTo(written.SomeField))

			})
		})
	})
})
