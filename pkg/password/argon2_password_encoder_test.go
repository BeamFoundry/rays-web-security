package password_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays-web-security/pkg/password"
	"golang.org/x/crypto/argon2"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("simulated rand reader failure")
}

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

	It("can encode and match with custom parameters and default zero-values", func() {
		// Use lower memory/iterations for fast test
		encoder := Argon2PasswordEncoder{}.New(1, 4096, 1, 32, 16)

		password := []byte("custom-argon2")
		encoded, err := encoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(encoded)).To(ContainSubstring("$argon2id$v=19$m=4096,t=1,p=1$"))

		Expect(encoder.Matches(password, encoded)).To(BeTrue())
		Expect(encoder.Matches([]byte("bad"), encoded)).To(BeFalse())

		// Test encoder with zero-values (triggers default field assignments in Encode)
		zeroEncoder := &Argon2PasswordEncoder{}
		zeroEncoded, err := zeroEncoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		Expect(zeroEncoder.Matches(password, zeroEncoded)).To(BeTrue())
	})

	It("handles rand reader error during Encode", func() {
		restore := SetRandReaderForTest(errReader{})
		defer restore()

		encoder := Argon2PasswordEncoder{}.NewDefault()
		_, err := encoder.Encode([]byte("test"))
		Expect(err).To(HaveOccurred())
	})

	It("matches valid argon2i hashes and argon2id without v= tag", func() {
		encoder := Argon2PasswordEncoder{}.NewDefault()

		// Generate a valid argon2i hash
		password := []byte("argon2i-password")
		salt := []byte("salt1234salt1234")
		derived := argon2.Key(password, salt, 1, 4096, 1, 32)
		argon2iHash := fmt.Sprintf("$argon2i$v=19$m=4096,t=1,p=1$%s$%s",
			base64.RawStdEncoding.EncodeToString(salt),
			base64.RawStdEncoding.EncodeToString(derived))

		Expect(encoder.Matches(password, []byte(argon2iHash))).To(BeTrue())
		Expect(encoder.Matches([]byte("wrong"), []byte(argon2iHash))).To(BeFalse())

		// Argon2id hash without v= tag
		derivedID := argon2.IDKey(password, salt, 1, 4096, 1, 32)
		hashNoVersion := fmt.Sprintf("$argon2id$m=4096,t=1,p=1$%s$%s",
			base64.RawStdEncoding.EncodeToString(salt),
			base64.RawStdEncoding.EncodeToString(derivedID))
		Expect(encoder.Matches(password, []byte(hashNoVersion))).To(BeTrue())
	})

	It("rejects argon2d and unsupported algorithms", func() {
		encoder := Argon2PasswordEncoder{}.NewDefault()
		Expect(encoder.Matches([]byte("test"), []byte("$argon2d$v=19$m=4096,t=1,p=1$c2FsdHNhbHRzYWx0MTIzNA$e8n2y8GZ5N9u3P3Fk8H0uN3L9W8K2P5Y8J7N6B4V1M8"))).To(BeFalse())
		Expect(encoder.Matches([]byte("test"), []byte("$unknown$v=19$m=4096,t=1,p=1$c2FsdHNhbHRzYWx0MTIzNA$e8n2y8GZ5N9u3P3Fk8H0uN3L9W8K2P5Y8J7N6B4V1M8"))).To(BeFalse())
	})

	It("rejects malformed hashes and out-of-bounds parameters", func() {
		encoder := Argon2PasswordEncoder{}.NewDefault()
		Expect(encoder.Matches([]byte("test"), []byte("invalid-hash"))).To(BeFalse())
		Expect(encoder.Matches([]byte("test"), []byte("$argon2id$bad"))).To(BeFalse())

		// Missing parameters part when v= is present
		Expect(encoder.Matches([]byte("test"), []byte("$argon2id$v=19$c2FsdA$aGFzaA"))).To(BeFalse())

		// Malformed key-value in params (no '=')
		Expect(encoder.Matches([]byte("test"), []byte("$argon2id$v=19$m=4096,noparam,t=1,p=1$c2FsdHNhbHRzYWx0MTIzNA$e8n2y8GZ5N9u3P3Fk8H0uN3L9W8K2P5Y8J7N6B4V1M8"))).To(BeFalse())

		// Non-integer parameter value
		Expect(encoder.Matches([]byte("test"), []byte("$argon2id$v=19$m=invalid,t=1,p=1$c2FsdHNhbHRzYWx0MTIzNA$e8n2y8GZ5N9u3P3Fk8H0uN3L9W8K2P5Y8J7N6B4V1M8"))).To(BeFalse())

		// Zero iterations (t=0)
		Expect(encoder.Matches([]byte("test"), []byte("$argon2id$v=19$m=4096,t=0,p=1$c2FsdHNhbHRzYWx0MTIzNA$e8n2y8GZ5N9u3P3Fk8H0uN3L9W8K2P5Y8J7N6B4V1M8"))).To(BeFalse())

		// Zero parallelism (p=0)
		Expect(encoder.Matches([]byte("test"), []byte("$argon2id$v=19$m=4096,t=1,p=0$c2FsdHNhbHRzYWx0MTIzNA$e8n2y8GZ5N9u3P3Fk8H0uN3L9W8K2P5Y8J7N6B4V1M8"))).To(BeFalse())

		// Parallelism > 255 (exceeds uint8)
		Expect(encoder.Matches([]byte("test"), []byte("$argon2id$v=19$m=4096,t=1,p=256$c2FsdHNhbHRzYWx0MTIzNA$e8n2y8GZ5N9u3P3Fk8H0uN3L9W8K2P5Y8J7N6B4V1M8"))).To(BeFalse())

		// Zero memory (m=0)
		Expect(encoder.Matches([]byte("test"), []byte("$argon2id$v=19$m=0,t=1,p=1$c2FsdHNhbHRzYWx0MTIzNA$e8n2y8GZ5N9u3P3Fk8H0uN3L9W8K2P5Y8J7N6B4V1M8"))).To(BeFalse())

		// Memory > Argon2MaxMemoryKiB
		Expect(encoder.Matches([]byte("test"), []byte("$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHRzYWx0MTIzNA$e8n2y8GZ5N9u3P3Fk8H0uN3L9W8K2P5Y8J7N6B4V1M8"))).To(BeFalse())

		// Missing required param (missing p=)
		Expect(encoder.Matches([]byte("test"), []byte("$argon2id$v=19$m=4096,t=1$c2FsdHNhbHRzYWx0MTIzNA$e8n2y8GZ5N9u3P3Fk8H0uN3L9W8K2P5Y8J7N6B4V1M8"))).To(BeFalse())

		// Extra parts in hash string
		Expect(encoder.Matches([]byte("test"), []byte("$argon2id$v=19$m=4096,t=1,p=1$extra$c2FsdHNhbHRzYWx0MTIzNA$e8n2y8GZ5N9u3P3Fk8H0uN3L9W8K2P5Y8J7N6B4V1M8"))).To(BeFalse())

		// Empty salt
		Expect(encoder.Matches([]byte("test"), []byte("$argon2id$v=19$m=4096,t=1,p=1$$e8n2y8GZ5N9u3P3Fk8H0uN3L9W8K2P5Y8J7N6B4V1M8"))).To(BeFalse())

		// Invalid base64 in salt
		Expect(encoder.Matches([]byte("test"), []byte("$argon2id$v=19$m=4096,t=1,p=1$!invalid!$e8n2y8GZ5N9u3P3Fk8H0uN3L9W8K2P5Y8J7N6B4V1M8"))).To(BeFalse())

		// Invalid base64 in hash
		Expect(encoder.Matches([]byte("test"), []byte("$argon2id$v=19$m=4096,t=1,p=1$c2FsdHNhbHRzYWx0MTIzNA$!invalid!"))).To(BeFalse())

		// Hash shorter than Argon2MinHashLength (16 bytes)
		shortHashB64 := "c2hvcnQ" // "short" (5 bytes)
		Expect(encoder.Matches([]byte("test"), []byte("$argon2id$v=19$m=4096,t=1,p=1$c2FsdHNhbHRzYWx0MTIzNA$"+shortHashB64))).To(BeFalse())

		// Hash longer than 1024 bytes
		hugeHash := base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("A", 1025)))
		Expect(encoder.Matches([]byte("test"), []byte("$argon2id$v=19$m=4096,t=1,p=1$c2FsdHNhbHRzYWx0MTIzNA$"+hugeHash))).To(BeFalse())
	})

	It("validates keyLength in Encode and verifies round-trip across accepted keyLengths", func() {
		// Key length below Argon2MinHashLength (16)
		encTooShort := Argon2PasswordEncoder{}.New(1, 1024, 1, Argon2MinHashLength-1, 16)
		_, err := encTooShort.Encode([]byte("password"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("outside allowed range"))

		// Key length above Argon2MaxHashLength (1024)
		encTooLong := Argon2PasswordEncoder{}.New(1, 1024, 1, Argon2MaxHashLength+1, 16)
		_, err = encTooLong.Encode([]byte("password"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("outside allowed range"))

		// Round-trip tests confirming every accepted keyLength produces a hash that Matches accepts
		acceptedLengths := []uint32{
			Argon2MinHashLength, // 16
			24,
			Argon2DefaultHashLength, // 32
			48,
			64,
			128,
			256,
			512,
			Argon2MaxHashLength, // 1024
		}
		for _, keyLen := range acceptedLengths {
			enc := Argon2PasswordEncoder{}.New(1, 1024, 1, keyLen, 16)
			pw := []byte(fmt.Sprintf("password-%d", keyLen))
			encoded, err := enc.Encode(pw)
			Expect(err).NotTo(HaveOccurred())
			Expect(enc.Matches(pw, encoded)).To(BeTrue())
			Expect(enc.Matches([]byte("wrong"), encoded)).To(BeFalse())
		}
	})
})
