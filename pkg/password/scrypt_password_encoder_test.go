package password_test

import (
	"encoding/base64"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/scrypt"

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

	It("can encode and match with NewDefault() and zero-value defaults", func() {
		encoder := SCryptPasswordEncoder{}.NewDefault()

		password := []byte("default-scrypt")
		encoded, err := encoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())

		Expect(encoder.Matches(password, encoded)).To(BeTrue())
		Expect(encoder.Matches([]byte("wrong"), encoded)).To(BeFalse())

		// Zero values default in Encode
		zeroEncoder := &SCryptPasswordEncoder{}
		zeroEncoded, err := zeroEncoder.Encode(password)
		Expect(err).NotTo(HaveOccurred())
		Expect(zeroEncoder.Matches(password, zeroEncoded)).To(BeTrue())
	})

	It("handles errors during Encode", func() {
		// Rand reader failure
		restore := SetRandReaderForTest(errReader{})
		defer restore()

		encoder := SCryptPasswordEncoder{}.NewDefault()
		_, err := encoder.Encode([]byte("test"))
		Expect(err).To(HaveOccurred())

		// Reset rand reader
		restore()

		// Invalid scrypt cpuCost (not power of 2)
		invalidCostEncoder := SCryptPasswordEncoder{}.New(3, 8, 1, 32, 16)
		_, err = invalidCostEncoder.Encode([]byte("test"))
		Expect(err).To(HaveOccurred())

		// Reject cpuCost above SCryptMaxCpuCost
		excessiveCpuEncoder := SCryptPasswordEncoder{}.New(1<<21, 8, 1, 32, 16)
		_, err = excessiveCpuEncoder.Encode([]byte("test"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("exceed maximum bounds"))

		// Reject memoryCost above SCryptMaxMemoryCost
		excessiveMemEncoder := SCryptPasswordEncoder{}.New(1024, 65, 1, 32, 16)
		_, err = excessiveMemEncoder.Encode([]byte("test"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("exceed maximum bounds"))

		// Reject parallelism above SCryptMaxParallelism
		excessiveParallelEncoder := SCryptPasswordEncoder{}.New(1024, 8, 65, 32, 16)
		_, err = excessiveParallelEncoder.Encode([]byte("test"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("exceed maximum bounds"))

		// Reject combined cpuCost * memoryCost above SCryptMaxNr
		excessiveNrEncoder := SCryptPasswordEncoder{}.New(65536, 32, 1, 32, 16)
		_, err = excessiveNrEncoder.Encode([]byte("test"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("exceed maximum bounds"))
	})

	It("handles malformed hashes gracefully", func() {
		encoder := SCryptPasswordEncoder{}.NewDefault()
		Expect(encoder.Matches([]byte("test"), []byte("not-scrypt"))).To(BeFalse())
		Expect(encoder.Matches([]byte("test"), []byte("$badparams$salt$hash"))).To(BeFalse())
		Expect(encoder.Matches([]byte("test"), []byte("$100801$badbase64!$badbase64!"))).To(BeFalse())
		Expect(encoder.Matches([]byte("test"), []byte("$100801$c2FsdA==$!badbase64!"))).To(BeFalse())
		Expect(encoder.Matches([]byte("test"), []byte("$100801$$c2FsdA=="))).To(BeFalse())
		Expect(encoder.Matches([]byte("test"), []byte("$100801$c2FsdA==$"))).To(BeFalse())
		Expect(encoder.Matches([]byte("test"), []byte("$neither$format"))).To(BeFalse())
	})

	It("enforces parameter bounds on Spring Security format hashes", func() {
		encoder := SCryptPasswordEncoder{}.NewDefault()

		// log2N = 0: (0 << 16) | (8 << 8) | 1 = 0x000801
		Expect(encoder.Matches([]byte("test"), []byte("$801$c2FsdHNhbHQ=$aGFzaGhhc2g="))).To(BeFalse())
		// log2N = 25 (excessive): (25 << 16) | (8 << 8) | 1 = 0x190801
		Expect(encoder.Matches([]byte("test"), []byte("$190801$c2FsdHNhbHQ=$aGFzaGhhc2g="))).To(BeFalse())

		// r > SCryptMaxMemoryCost (r = 100): (14 << 16) | (100 << 8) | 1 = 0x0e6401
		Expect(encoder.Matches([]byte("test"), []byte("$e6401$c2FsdHNhbHQ=$aGFzaGhhc2g="))).To(BeFalse())

		// p > SCryptMaxParallelism (p = 100): (14 << 16) | (8 << 8) | 100 = 0x0e0864
		Expect(encoder.Matches([]byte("test"), []byte("$e0864$c2FsdHNhbHQ=$aGFzaGhhc2g="))).To(BeFalse())

		// cpuCost * memoryCost > SCryptMaxNr (N = 65536, r = 32): (16 << 16) | (32 << 8) | 1 = 0x102001
		// Uses precomputed hash that correctly derives from "test" at rejected cost (N=65536, r=32, p=1)
		Expect(encoder.Matches([]byte("test"), []byte("$102001$c2FsdHNhbHRzYWx0MTIzNA==$aB8HEEEEsEnWi0W32z89XcEPZ/jDTMZlktmbzKofm/0="))).To(BeFalse())
	})

	It("matches and enforces parameter bounds on PHC format scrypt hashes", func() {
		encoder := SCryptPasswordEncoder{}.New(1024, 8, 1, 32, 16)

		// Valid PHC formatted hash with ln=10 (N=1024), r=8, p=1
		password := []byte("phc-test")
		salt := []byte("saltsaltsalt1234")
		derived, err := scrypt.Key(password, salt, 1024, 8, 1, 32)
		Expect(err).NotTo(HaveOccurred())
		b64Salt := base64.StdEncoding.EncodeToString(salt)
		b64Derived := base64.StdEncoding.EncodeToString(derived)

		phcHash := fmt.Sprintf("$scrypt$ln=10,r=8,p=1$%s$%s", b64Salt, b64Derived)
		Expect(encoder.Matches(password, []byte(phcHash))).To(BeTrue())
		Expect(encoder.Matches([]byte("wrong"), []byte(phcHash))).To(BeFalse())

		// Valid PHC format using N=1024 directly
		phcWithN := fmt.Sprintf("$scrypt$N=1024,r=8,p=1,unknown=99$%s$%s", b64Salt, b64Derived)
		Expect(encoder.Matches(password, []byte(phcWithN))).To(BeTrue())

		// Param part without '='
		phcWithNoParam := fmt.Sprintf("$scrypt$ln=10,noparam,r=8,p=1$%s$%s", b64Salt, b64Derived)
		Expect(encoder.Matches(password, []byte(phcWithNoParam))).To(BeTrue())

		// Non-integer parameter value
		Expect(encoder.Matches(password, []byte("$scrypt$ln=invalid,r=8,p=1$c2FsdHNhbHQ=$aGFzaGhhc2g="))).To(BeFalse())

		// Missing cpuCost in PHC (no ln or N)
		Expect(encoder.Matches(password, []byte("$scrypt$r=8,p=1$c2FsdHNhbHQ=$aGFzaGhhc2g="))).To(BeFalse())

		// Out-of-bounds ln (< 1 or > 20)
		Expect(encoder.Matches(password, []byte("$scrypt$ln=0,r=8,p=1$c2FsdHNhbHQ=$aGFzaGhhc2g="))).To(BeFalse())
		Expect(encoder.Matches(password, []byte("$scrypt$ln=25,r=8,p=1$c2FsdHNhbHQ=$aGFzaGhhc2g="))).To(BeFalse())

		// Out-of-bounds r (< 1 or > 64)
		Expect(encoder.Matches(password, []byte("$scrypt$ln=10,r=0,p=1$c2FsdHNhbHQ=$aGFzaGhhc2g="))).To(BeFalse())
		Expect(encoder.Matches(password, []byte("$scrypt$ln=10,r=100,p=1$c2FsdHNhbHQ=$aGFzaGhhc2g="))).To(BeFalse())

		// Out-of-bounds p (< 1 or > 64)
		Expect(encoder.Matches(password, []byte("$scrypt$ln=10,r=8,p=0$c2FsdHNhbHQ=$aGFzaGhhc2g="))).To(BeFalse())
		Expect(encoder.Matches(password, []byte("$scrypt$ln=10,r=8,p=100$c2FsdHNhbHQ=$aGFzaGhhc2g="))).To(BeFalse())

		// Non-power of two N or excessive N
		Expect(encoder.Matches(password, []byte("$scrypt$N=1000,r=8,p=1$c2FsdHNhbHQ=$aGFzaGhhc2g="))).To(BeFalse())
		Expect(encoder.Matches(password, []byte("$scrypt$N=4194304,r=8,p=1$c2FsdHNhbHQ=$aGFzaGhhc2g="))).To(BeFalse())

		// cpuCost * memoryCost > SCryptMaxNr in PHC (N = 65536, r = 32)
		// Uses precomputed hash that correctly derives from password ("phc-test") at rejected cost (N=65536, r=32, p=1)
		Expect(encoder.Matches(password, []byte("$scrypt$ln=16,r=32,p=1$c2FsdHNhbHRzYWx0MTIzNA==$xl+vnKBjqTrnUbdGvFG0y/USR2MIhNnGe4X2pms37VQ="))).To(BeFalse())
		Expect(encoder.Matches(password, []byte("$scrypt$N=65536,r=32,p=1$c2FsdHNhbHRzYWx0MTIzNA==$xl+vnKBjqTrnUbdGvFG0y/USR2MIhNnGe4X2pms37VQ="))).To(BeFalse())

		// Empty or invalid base64 salt or derived
		Expect(encoder.Matches(password, []byte("$scrypt$ln=10,r=8,p=1$$aGFzaGhhc2g="))).To(BeFalse())
		Expect(encoder.Matches(password, []byte("$scrypt$ln=10,r=8,p=1$!bad!$aGFzaGhhc2g="))).To(BeFalse())
		Expect(encoder.Matches(password, []byte("$scrypt$ln=10,r=8,p=1$c2FsdHNhbHQ=$"))).To(BeFalse())
		Expect(encoder.Matches(password, []byte("$scrypt$ln=10,r=8,p=1$c2FsdHNhbHQ=$!bad!"))).To(BeFalse())
	})
})
