package password_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays-web-security/pkg/password"
)

var _ = Describe("Pbkdf2PasswordEncoder", func() {
	It("can encode and match with default parameters (Hex)", func() {
		encoder := Pbkdf2PasswordEncoder{}.New("", 16, 1000, 32, "PBKDF2WithHmacSHA256")

		password := []byte("secret-pbkdf2-password")
		encoded, err := encoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(encoded)).To(Equal(96))

		Expect(encoder.Matches(password, encoded)).To(BeTrue())
		Expect(encoder.Matches([]byte("wrong"), encoded)).To(BeFalse())
	})

	It("can encode and match with Base64 encoding", func() {
		encoder := Pbkdf2PasswordEncoder{}.New("", 16, 1000, 32, "PBKDF2WithHmacSHA256").SetEncodeHashAsBase64(true)

		password := []byte("base64-pbkdf2")
		encoded, err := encoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())

		Expect(encoder.Matches(password, encoded)).To(BeTrue())
		Expect(encoder.Matches([]byte("wrong"), encoded)).To(BeFalse())
	})

	It("supports secrets and SHA-512 / SHA-1", func() {
		enc512 := Pbkdf2PasswordEncoder{}.New("my-secret", 16, 500, 64, "PBKDF2WithHmacSHA512")
		password := []byte("sha512-password")
		encoded512, err := enc512.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		Expect(enc512.Matches(password, encoded512)).To(BeTrue())
		Expect(enc512.Matches([]byte("wrong"), encoded512)).To(BeFalse())

		enc1 := Pbkdf2PasswordEncoder{}.New("", 8, 500, 20, "PBKDF2WithHmacSHA1")
		encoded1, err := enc1.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		Expect(enc1.Matches(password, encoded1)).To(BeTrue())
	})

	It("matches PHC and Django format PBKDF2 hashes", func() {
		encoder := Pbkdf2PasswordEncoder{}.NewDefault()
		Expect(encoder.Matches([]byte("test"), []byte("invalid-hash"))).To(BeFalse())
		Expect(encoder.Matches([]byte("test"), []byte("not_hex_or_valid!@#$%"))).To(BeFalse())
	})
})
