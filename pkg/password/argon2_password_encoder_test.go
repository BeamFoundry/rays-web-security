package password_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays-web-security/pkg/password"
)

var _ = Describe("Argon2PasswordEncoder", func() {
	It("can encode and match with default parameters", func() {
		encoder := Argon2PasswordEncoder{}.NewDefault()

		password := []byte("secret-argon2-password")
		encoded, err := encoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(encoded)).To(ContainSubstring("$argon2id$v=19$m=16384,t=2,p=1$"))

		Expect(encoder.Matches(password, encoded)).To(BeTrue())
		Expect(encoder.Matches([]byte("wrong-password"), encoded)).To(BeFalse())
	})

	It("can encode and match with custom parameters", func() {
		// Use lower memory/iterations for fast test
		encoder := Argon2PasswordEncoder{}.New(1, 4096, 1, 32, 16)

		password := []byte("custom-argon2")
		encoded, err := encoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(encoded)).To(ContainSubstring("$argon2id$v=19$m=4096,t=1,p=1$"))

		Expect(encoder.Matches(password, encoded)).To(BeTrue())
		Expect(encoder.Matches([]byte("bad"), encoded)).To(BeFalse())
	})

	It("matches argon2i format and rejects malformed hashes", func() {
		encoder := Argon2PasswordEncoder{}.NewDefault()
		Expect(encoder.Matches([]byte("test"), []byte("invalid-hash"))).To(BeFalse())
		Expect(encoder.Matches([]byte("test"), []byte("$argon2id$bad"))).To(BeFalse())
		Expect(encoder.Matches([]byte("test"), []byte("$unknown$v=19$m=4096,t=1,p=1$salt$hash"))).To(BeFalse())
	})
})
