package password_test

import (
	"crypto/sha1" // #nosec G505 - PBKDF2 with SHA-1 is supported for Spring Security legacy compatibility
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/pbkdf2"

	. "github.com/BeamFoundry/rays-web-security/pkg/password"
)

var _ = Describe("Pbkdf2PasswordEncoder", func() {
	It("can encode and match with default parameters (Hex)", func() {
		encoder := Pbkdf2PasswordEncoder{}.New("", 16, 1000, 32, "PBKDF2WithHmacSHA256")

		password := []byte("secret-pbkdf2-password")
		encoded, err := encoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		Expect(encoded).To(HaveLen(96))

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

		// Fallback when decodeBase64 errors on invalid base64 input
		Expect(encoder.Matches([]byte("test"), []byte("invalid-hash!"))).To(BeFalse())
	})

	It("can encode and match with zero-value defaults and handle bounds", func() {
		zeroEncoder := &Pbkdf2PasswordEncoder{}
		password := []byte("zero-default")
		encoded, err := zeroEncoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		Expect(zeroEncoder.Matches(password, encoded)).To(BeTrue())

		// Excessive iterations in Encode
		tooManyIterEnc := Pbkdf2PasswordEncoder{}.New("", 16, 6000000, 32, "PBKDF2WithHmacSHA256")
		_, err = tooManyIterEnc.Encode(password)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("exceeds maximum allowed"))

		// Excessive iterations in Matches
		Expect(tooManyIterEnc.Matches(password, encoded)).To(BeFalse())

		// Rand reader error
		restore := SetRandReaderForTest(errReader{})
		defer restore()

		enc := Pbkdf2PasswordEncoder{}.NewDefault()
		_, err = enc.Encode(password)
		Expect(err).To(HaveOccurred())
	})

	It("supports empty string as default SHA-256 and rejects unknown algorithms", func() {
		// Empty algorithm defaults to SHA-256
		encDefault := Pbkdf2PasswordEncoder{}.New("", 16, 500, 32, "")
		password := []byte("default-sha256")
		encoded, err := encDefault.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		Expect(encDefault.Matches(password, encoded)).To(BeTrue())

		// Unknown algorithm returns error on Encode and false on Matches
		encInvalid := Pbkdf2PasswordEncoder{}.New("", 16, 500, 32, "UNSUPPORTED_ALGO")
		_, err = encInvalid.Encode(password)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unsupported PBKDF2 algorithm"))
		Expect(encInvalid.Matches(password, encoded)).To(BeFalse())
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

	It("matches and validates Django format PBKDF2 hashes", func() {
		encoder := Pbkdf2PasswordEncoder{}.NewDefault()
		password := []byte("django-password")
		salt := "mysalt1234"

		// Valid pbkdf2_sha256
		derived256 := pbkdf2.Key(password, []byte(salt), 1000, 32, sha256.New)
		b64Sha256 := base64.StdEncoding.EncodeToString(derived256)
		django256 := fmt.Sprintf("pbkdf2_sha256$1000$%s$%s", salt, b64Sha256)
		Expect(encoder.Matches(password, []byte(django256))).To(BeTrue())
		Expect(encoder.Matches([]byte("wrong"), []byte(django256))).To(BeFalse())

		// Valid pbkdf2_sha512
		derived512 := pbkdf2.Key(password, []byte(salt), 1000, 64, sha512.New)
		b64Sha512 := base64.StdEncoding.EncodeToString(derived512)
		django512 := fmt.Sprintf("pbkdf2_sha512$1000$%s$%s", salt, b64Sha512)
		Expect(encoder.Matches(password, []byte(django512))).To(BeTrue())

		// Valid pbkdf2_sha1
		derived1 := pbkdf2.Key(password, []byte(salt), 1000, 20, sha1.New)
		b64Sha1 := base64.StdEncoding.EncodeToString(derived1)
		django1 := fmt.Sprintf("pbkdf2_sha1$1000$%s$%s", salt, b64Sha1)
		Expect(encoder.Matches(password, []byte(django1))).To(BeTrue())

		// Valid Django with secret
		encWithSecret := Pbkdf2PasswordEncoder{}.New("app-secret", 16, 1000, 32, "PBKDF2WithHmacSHA256")
		saltAndSecret := append([]byte(salt), []byte("app-secret")...)
		derivedSecret := pbkdf2.Key(password, saltAndSecret, 1000, 32, sha256.New)
		djangoSecret := fmt.Sprintf("pbkdf2_sha256$1000$%s$%s", salt, base64.StdEncoding.EncodeToString(derivedSecret))
		Expect(encWithSecret.Matches(password, []byte(djangoSecret))).To(BeTrue())

		// Django with unsupported algorithm
		Expect(encoder.Matches(password, []byte("pbkdf2_unsupported$1000$salt$YWJj"))).To(BeFalse())

		// Django with invalid/out-of-bounds iterations
		Expect(encoder.Matches(password, []byte("pbkdf2_sha256$0$salt$YWJj"))).To(BeFalse())
		Expect(encoder.Matches(password, []byte("pbkdf2_sha256$99999999$salt$YWJj"))).To(BeFalse())
		Expect(encoder.Matches(password, []byte("pbkdf2_sha256$notanumber$salt$YWJj"))).To(BeFalse())

		// Django with empty salt or hash, or invalid base64 hash
		Expect(encoder.Matches(password, []byte("pbkdf2_sha256$1000$$YWJj"))).To(BeFalse())
		Expect(encoder.Matches(password, []byte("pbkdf2_sha256$1000$salt$"))).To(BeFalse())
		Expect(encoder.Matches(password, []byte("pbkdf2_sha256$1000$salt$!invalid-base64!"))).To(BeFalse())
	})

	It("matches and validates PHC format PBKDF2 hashes", func() {
		encoder := Pbkdf2PasswordEncoder{}.NewDefault()
		password := []byte("phc-pbkdf2-pass")
		salt := []byte("phcsalt1234")
		b64Salt := base64.StdEncoding.EncodeToString(salt)

		// Valid pbkdf2-sha256 (also test param part without '=')
		derived256 := pbkdf2.Key(password, salt, 1000, 32, sha256.New)
		b64Hash256 := base64.StdEncoding.EncodeToString(derived256)
		phc256 := fmt.Sprintf("$pbkdf2-sha256$noparam,i=1000$%s$%s", b64Salt, b64Hash256)
		Expect(encoder.Matches(password, []byte(phc256))).To(BeTrue())
		Expect(encoder.Matches([]byte("wrong"), []byte(phc256))).To(BeFalse())

		// Valid pbkdf2-sha512
		derived512 := pbkdf2.Key(password, salt, 1000, 64, sha512.New)
		phc512 := fmt.Sprintf("$pbkdf2-sha512$i=1000$%s$%s", b64Salt, base64.StdEncoding.EncodeToString(derived512))
		Expect(encoder.Matches(password, []byte(phc512))).To(BeTrue())

		// Valid pbkdf2-sha1
		derived1 := pbkdf2.Key(password, salt, 1000, 20, sha1.New)
		phc1 := fmt.Sprintf("$pbkdf2-sha1$i=1000$%s$%s", b64Salt, base64.StdEncoding.EncodeToString(derived1))
		Expect(encoder.Matches(password, []byte(phc1))).To(BeTrue())

		// Valid pbkdf2 (bare, inherits encoder's algorithm)
		phcBare := fmt.Sprintf("$pbkdf2$i=1000$%s$%s", b64Salt, b64Hash256)
		Expect(encoder.Matches(password, []byte(phcBare))).To(BeTrue())

		// Valid PHC with secret
		encWithSecret := Pbkdf2PasswordEncoder{}.New("app-secret", 16, 1000, 32, "PBKDF2WithHmacSHA256")
		saltAndSecret := append([]byte(nil), salt...)
		saltAndSecret = append(saltAndSecret, []byte("app-secret")...)
		derivedSecret := pbkdf2.Key(password, saltAndSecret, 1000, 32, sha256.New)
		phcSecret := fmt.Sprintf("$pbkdf2-sha256$i=1000$%s$%s", b64Salt, base64.StdEncoding.EncodeToString(derivedSecret))
		Expect(encWithSecret.Matches(password, []byte(phcSecret))).To(BeTrue())

		// Unsupported PHC algorithm
		Expect(encoder.Matches(password, []byte(fmt.Sprintf("$pbkdf2-unknown$i=1000$%s$%s", b64Salt, b64Hash256)))).To(BeFalse())

		// Invalid i= non-integer
		Expect(encoder.Matches(password, []byte("$pbkdf2-sha256$i=invalid$c2FsdDEyMzQ$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="))).To(BeFalse())

		// i=0 or out-of-bounds
		Expect(encoder.Matches(password, []byte("$pbkdf2-sha256$i=0$c2FsdDEyMzQ$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="))).To(BeFalse())
		Expect(encoder.Matches(password, []byte("$pbkdf2-sha256$i=99999999$c2FsdDEyMzQ$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="))).To(BeFalse())

		// Missing i= parameter
		Expect(encoder.Matches(password, []byte("$pbkdf2-sha256$other=100$c2FsdDEyMzQ$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="))).To(BeFalse())

		// Empty or invalid base64 salt or hash
		Expect(encoder.Matches(password, []byte("$pbkdf2-sha256$i=1000$$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="))).To(BeFalse())
		Expect(encoder.Matches(password, []byte("$pbkdf2-sha256$i=1000$!invalid-salt!$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="))).To(BeFalse())
		Expect(encoder.Matches(password, []byte("$pbkdf2-sha256$i=1000$c2FsdDEyMzQ$"))).To(BeFalse())
		Expect(encoder.Matches(password, []byte("$pbkdf2-sha256$i=1000$c2FsdDEyMzQ$!invalid-hash!"))).To(BeFalse())

		// General malformed hashes
		Expect(encoder.Matches(password, []byte("invalid-hash"))).To(BeFalse())
		Expect(encoder.Matches(password, []byte("not_hex_or_valid!@#$%"))).To(BeFalse())

		// Short decoded slice (len(digested) <= saltLength)
		shortHex := hex.EncodeToString([]byte("short"))
		Expect(encoder.Matches(password, []byte(shortHex))).To(BeFalse())
	})
})
