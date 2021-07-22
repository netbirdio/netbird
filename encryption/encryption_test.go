package encryption_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/wiretrustee/wiretrustee/encryption"
	"github.com/wiretrustee/wiretrustee/encryption/testprotos"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const ()

var _ = Describe("Encryption", func() {

	var (
		encryptingKey wgtypes.Key
		decryptingKey wgtypes.Key
	)

	BeforeEach(func() {
		var err error
		encryptingKey, err = wgtypes.GenerateKey()
		Expect(err).NotTo(HaveOccurred())
		decryptingKey, err = wgtypes.GenerateKey()
		Expect(err).NotTo(HaveOccurred())
	})

	Context("decrypting a plain message", func() {
		Context("when it was encrypted with Wireguard keys", func() {
			Specify("should be successful", func() {
				msg := "message"
				encryptedMsg, err := encryption.Encrypt([]byte(msg), decryptingKey.PublicKey(), encryptingKey)
				Expect(err).NotTo(HaveOccurred())

				decryptedMsg, err := encryption.Decrypt(encryptedMsg, encryptingKey.PublicKey(), decryptingKey)
				Expect(err).NotTo(HaveOccurred())

				Expect(string(decryptedMsg)).To(BeEquivalentTo(msg))
			})
		})
	})

	Context("decrypting a protobuf message", func() {
		Context("when it was encrypted with Wireguard keys", func() {
			Specify("should be successful", func() {

				protoMsg := &testprotos.TestMessage{Body: "message"}
				encryptedMsg, err := encryption.EncryptMessage(decryptingKey.PublicKey(), encryptingKey, protoMsg)
				Expect(err).NotTo(HaveOccurred())

				decryptedMsg := &testprotos.TestMessage{}
				err = encryption.DecryptMessage(encryptingKey.PublicKey(), decryptingKey, encryptedMsg, decryptedMsg)
				Expect(err).NotTo(HaveOccurred())

				Expect(decryptedMsg.GetBody()).To(BeEquivalentTo(protoMsg.GetBody()))
			})
		})
	})

})
