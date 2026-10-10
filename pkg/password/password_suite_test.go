package password_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	_ "github.com/BeamFoundry/rays-web-security/internal/autoconfig"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/password"
)

func TestPassword(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Password Suite")
}

var DefaultPasswordEncoder PasswordEncoder = DelegatingPasswordEncoder{}.New(
	"bcrypt", map[string]PasswordEncoder{"bcrypt": BCryptPasswordEncoder{}.New(10)},
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
})

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

var _ = Describe("DelegatingPasswordEncoder", func() {
	It("can encode/decode", func() {
		encoder := DefaultPasswordEncoder
		tooLong := "012345678901234567890123456789012345678901234567890123456"
		_, err := encoder.Encode([]byte(tooLong + tooLong))
		Expect(err).To(HaveOccurred())

		password := []byte("DelegatingPasswordEncoder")
		encoded, err := encoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())

		Expect(encoder.Matches(password, encoded)).To(BeTrue())

		Expect(encoder.Matches([]byte("bad"), encoded)).To(BeFalse())
		Expect(encoder.Matches([]byte("bad"), []byte("bad"))).To(BeFalse())
	})
})
