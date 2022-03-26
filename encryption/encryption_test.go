package encryption_test

import (
	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/encryption/testprotos"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const ()

var _ = Describe("Encryption", func() {

	var (
		encryptionKey wgtypes.Key
		decryptionKey wgtypes.Key
	)

	BeforeEach(func() {
		var err error
		encryptionKey, err = wgtypes.GenerateKey()
		Expect(err).NotTo(HaveOccurred())
		decryptionKey, err = wgtypes.GenerateKey()
		Expect(err).NotTo(HaveOccurred())
	})

	Context("decrypting a plain message", func() {
		Context("when it was encrypted with Wireguard keys", func() {
			Specify("should be successful", func() {
				msg := "message"
				encryptedMsg, err := encryption.Encrypt([]byte(msg), decryptionKey.PublicKey(), encryptionKey)
				Expect(err).NotTo(HaveOccurred())

				decryptedMsg, err := encryption.Decrypt(encryptedMsg, encryptionKey.PublicKey(), decryptionKey)
				Expect(err).NotTo(HaveOccurred())

				Expect(string(decryptedMsg)).To(BeEquivalentTo(msg))
			})
		})
	})

	Context("decrypting a protobuf message", func() {
		Context("when it was encrypted with Wireguard keys", func() {
			Specify("should be successful", func() {

				protoMsg := &testprotos.TestMessage{Body: "message"}
				encryptedMsg, err := encryption.EncryptMessage(decryptionKey.PublicKey(), encryptionKey, protoMsg)
				Expect(err).NotTo(HaveOccurred())

				decryptedMsg := &testprotos.TestMessage{}
				err = encryption.DecryptMessage(encryptionKey.PublicKey(), decryptionKey, encryptedMsg, decryptedMsg)
				Expect(err).NotTo(HaveOccurred())

				Expect(decryptedMsg.GetBody()).To(BeEquivalentTo(protoMsg.GetBody()))
			})
		})
	})

})
