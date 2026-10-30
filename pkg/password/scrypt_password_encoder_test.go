package password_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays-web-security/pkg/password"
)

var _ = Describe("SCryptPasswordEncoder", func() {
	It("can encode and match with default parameters", func() {
		encoder := SCryptPasswordEncoder{}.New(1024, 8, 1, 32, 16)

		password := []byte("secret-scrypt-password")
		encoded, err := encoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(encoded)).To(HavePrefix("$"))

		Expect(encoder.Matches(password, encoded)).To(BeTrue())
		Expect(encoder.Matches([]byte("wrong"), encoded)).To(BeFalse())
	})

	It("can encode and match with NewDefault()", func() {
		encoder := SCryptPasswordEncoder{}.NewDefault()

		password := []byte("default-scrypt")
		encoded, err := encoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())

		Expect(encoder.Matches(password, encoded)).To(BeTrue())
		Expect(encoder.Matches([]byte("wrong"), encoded)).To(BeFalse())
	})

	It("handles malformed hashes gracefully", func() {
		encoder := SCryptPasswordEncoder{}.NewDefault()
		Expect(encoder.Matches([]byte("test"), []byte("not-scrypt"))).To(BeFalse())
		Expect(encoder.Matches([]byte("test"), []byte("$badparams$salt$hash"))).To(BeFalse())
		Expect(encoder.Matches([]byte("test"), []byte("$100801$badbase64!$badbase64!"))).To(BeFalse())
	})

	It("matches PHC format scrypt hashes", func() {
		encoder := SCryptPasswordEncoder{}.New(1024, 8, 1, 32, 16)
		password := []byte("phc-test")
		encoded, err := encoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		Expect(encoder.Matches(password, encoded)).To(BeTrue())
	})
})
