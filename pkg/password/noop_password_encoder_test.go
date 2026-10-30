package password_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays-web-security/pkg/password"
)

var _ = Describe("NoOpPasswordEncoder", func() {
	It("can encode/decode", func() {
		encoder := NoOpPasswordEncoder{}.New()

		password := []byte("NoOpPasswordEncoder")
		encoded, err := encoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())

		Expect(encoder.Matches(password, encoded)).To(BeTrue())
		Expect(encoder.Matches([]byte("bad"), encoded)).To(BeFalse())
	})
})
