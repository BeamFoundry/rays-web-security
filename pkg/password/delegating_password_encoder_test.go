package password_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays-web-security/pkg/password"
)

var _ = Describe("DelegatingPasswordEncoder", func() {
	It("can encode/decode using default id (bcrypt)", func() {
		encoder := DelegatingPasswordEncoder{}.NewDefault()
		tooLong := "012345678901234567890123456789012345678901234567890123456"
		_, err := encoder.Encode([]byte(tooLong + tooLong))
		Expect(err).To(HaveOccurred())

		password := []byte("DelegatingPasswordEncoder")
		encoded, err := encoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(encoded)).To(HavePrefix("{bcrypt}"))

		Expect(encoder.Matches(password, encoded)).To(BeTrue())
		Expect(encoder.Matches([]byte("bad"), encoded)).To(BeFalse())
		Expect(encoder.Matches([]byte("bad"), []byte("bad"))).To(BeFalse())
	})

	It("delegates matching to argon2, pbkdf2, scrypt, and noop", func() {
		encoder := DelegatingPasswordEncoder{}.NewDefault()
		password := []byte("multi-algorithm-password")

		// Argon2
		argon2Enc := Argon2PasswordEncoder{}.New(1, 4096, 1, 32, 16)
		argon2Raw, err := argon2Enc.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		argon2Delegated := append([]byte("{argon2}"), argon2Raw...)
		Expect(encoder.Matches(password, argon2Delegated)).To(BeTrue())
		Expect(encoder.Matches([]byte("bad"), argon2Delegated)).To(BeFalse())

		// PBKDF2
		pbkdf2Enc := Pbkdf2PasswordEncoder{}.NewDefault()
		pbkdf2Raw, err := pbkdf2Enc.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		pbkdf2Delegated := append([]byte("{pbkdf2}"), pbkdf2Raw...)
		Expect(encoder.Matches(password, pbkdf2Delegated)).To(BeTrue())
		Expect(encoder.Matches([]byte("bad"), pbkdf2Delegated)).To(BeFalse())

		// SCrypt
		scryptEnc := SCryptPasswordEncoder{}.New(1024, 8, 1, 32, 16)
		scryptRaw, err := scryptEnc.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		scryptDelegated := append([]byte("{scrypt}"), scryptRaw...)
		Expect(encoder.Matches(password, scryptDelegated)).To(BeTrue())
		Expect(encoder.Matches([]byte("bad"), scryptDelegated)).To(BeFalse())

		// NoOp
		noopDelegated := []byte("{noop}plain-password")
		Expect(encoder.Matches([]byte("plain-password"), noopDelegated)).To(BeTrue())
		Expect(encoder.Matches([]byte("bad"), noopDelegated)).To(BeFalse())

		// Unknown ID
		Expect(encoder.Matches(password, []byte("{unknown}somehash"))).To(BeFalse())
	})
})
