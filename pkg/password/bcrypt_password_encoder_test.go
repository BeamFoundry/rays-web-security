package password_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays-web-security/pkg/password"
)

var _ = Describe("BCryptPasswordEncoder", func() {
	It("can encode/decode", func() {
		encoder := BCryptPasswordEncoder{}.New(10)
		tooLong := "012345678901234567890123456789012345678901234567890123456"
		_, err := encoder.Encode([]byte(tooLong + tooLong))
		Expect(err).To(HaveOccurred())

		password := []byte("BCryptPasswordEncoder")
		encoded, err := encoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())

		Expect(encoder.Matches(password, encoded)).To(BeTrue())
		Expect(encoder.Matches([]byte("bad"), encoded)).To(BeFalse())
	})

	It("can use NewDefault()", func() {
		encoder := BCryptPasswordEncoder{}.NewDefault()
		password := []byte("DefaultBCrypt")
		encoded, err := encoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		Expect(encoder.Matches(password, encoded)).To(BeTrue())
	})
})
