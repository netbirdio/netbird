package util_test

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/netbirdio/netbird/util"
)

var _ = Describe("Client", func() {

	var (
		tmpDir string
	)

	type TestConfig struct {
		SomeMap   map[string]string
		SomeArray []string
		SomeField int
	}

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "wiretrustee_util_test_tmp_*")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		err := os.RemoveAll(tmpDir)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("Config", func() {
		Context("in JSON format", func() {
			It("should be written and read successfully", func() {

				m := make(map[string]string)
				m["key1"] = "value1"
				m["key2"] = "value2"

				arr := []string{"value1", "value2"}

				written := &TestConfig{
					SomeMap:   m,
					SomeArray: arr,
					SomeField: 99,
				}

				err := util.WriteJson(tmpDir+"/testconfig.json", written)
				Expect(err).NotTo(HaveOccurred())

				read, err := util.ReadJson(tmpDir+"/testconfig.json", &TestConfig{})
				Expect(err).NotTo(HaveOccurred())
				Expect(read).NotTo(BeNil())
				Expect(read.(*TestConfig).SomeMap["key1"]).To(BeEquivalentTo(written.SomeMap["key1"]))
				Expect(read.(*TestConfig).SomeMap["key2"]).To(BeEquivalentTo(written.SomeMap["key2"]))
				Expect(read.(*TestConfig).SomeArray).To(ContainElements(arr))
				Expect(read.(*TestConfig).SomeField).To(BeEquivalentTo(written.SomeField))

			})
		})
	})

	Describe("Copying file contents", func() {
		Context("from one file to another", func() {
			It("should be successful", func() {

				src := tmpDir + "/copytest_src"
				dst := tmpDir + "/copytest_dst"

				err := util.WriteJson(src, []string{"1", "2", "3"})
				Expect(err).NotTo(HaveOccurred())

				err = util.CopyFileContents(src, dst)
				Expect(err).NotTo(HaveOccurred())

				hashSrc := md5.New()
				hashDst := md5.New()

				srcFile, err := os.Open(src)
				Expect(err).NotTo(HaveOccurred())

				dstFile, err := os.Open(dst)
				Expect(err).NotTo(HaveOccurred())

				_, err = io.Copy(hashSrc, srcFile)
				Expect(err).NotTo(HaveOccurred())

				_, err = io.Copy(hashDst, dstFile)
				Expect(err).NotTo(HaveOccurred())

				err = srcFile.Close()
				Expect(err).NotTo(HaveOccurred())

				err = dstFile.Close()
				Expect(err).NotTo(HaveOccurred())

				Expect(hex.EncodeToString(hashSrc.Sum(nil)[:16])).To(BeEquivalentTo(hex.EncodeToString(hashDst.Sum(nil)[:16])))
			})
		})
	})

	Describe("Handle config file without full path", func() {
		Context("config file handling", func() {
			It("should be successful", func() {
				written := &TestConfig{
					SomeField: 123,
				}
				cfgFile := "test_cfg.json"
				defer os.Remove(cfgFile)

				err := util.WriteJson(cfgFile, written)
				Expect(err).NotTo(HaveOccurred())

				read, err := util.ReadJson(cfgFile, &TestConfig{})
				Expect(err).NotTo(HaveOccurred())
				Expect(read).NotTo(BeNil())
			})
		})
	})
})
