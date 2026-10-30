package password

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"strconv"
	"strings"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"

	"golang.org/x/crypto/pbkdf2"
)

const (
	Pbkdf2DefaultSaltLength = 16
	Pbkdf2DefaultIterations = 310000
	Pbkdf2DefaultKeyLength  = 32 // 256 bits
	Pbkdf2DefaultAlgorithm  = "PBKDF2WithHmacSHA256"
)

// Pbkdf2PasswordEncoder implements [core.PasswordEncoder] using the PBKDF2 key derivation function.
// It defaults to PBKDF2 with HMAC-SHA256 and Hex encoding, compatible with Spring Security's Pbkdf2PasswordEncoder.
type Pbkdf2PasswordEncoder struct {
	secret             []byte
	saltLength         int
	iterations         int
	keyLength          int
	algorithm          string
	encodeHashAsBase64 bool
}

var _ PasswordEncoder = &Pbkdf2PasswordEncoder{}

type PBKDF2PasswordEncoder = Pbkdf2PasswordEncoder

// New constructs a Pbkdf2PasswordEncoder with custom configuration.
func (this Pbkdf2PasswordEncoder) New(secret string, saltLength, iterations, keyLength int, algorithm string) *Pbkdf2PasswordEncoder {
	this.secret = []byte(secret)
	this.saltLength = saltLength
	this.iterations = iterations
	this.keyLength = keyLength
	this.algorithm = algorithm
	return &this
}

// NewDefault constructs a Pbkdf2PasswordEncoder with recommended defaults
// matching Spring Security 5.8+ (empty secret, saltLength=16, iterations=310000, keyLength=32, algorithm="PBKDF2WithHmacSHA256").
func (this Pbkdf2PasswordEncoder) NewDefault() *Pbkdf2PasswordEncoder {
	return this.New(
		"",
		Pbkdf2DefaultSaltLength,
		Pbkdf2DefaultIterations,
		Pbkdf2DefaultKeyLength,
		Pbkdf2DefaultAlgorithm,
	)
}

// SetEncodeHashAsBase64 sets whether the encoded password should be formatted in Base64 instead of Hex.
func (this *Pbkdf2PasswordEncoder) SetEncodeHashAsBase64(encodeHashAsBase64 bool) *Pbkdf2PasswordEncoder {
	this.encodeHashAsBase64 = encodeHashAsBase64
	return this
}

func getPbkdf2HashFunc(algorithm string) func() hash.Hash {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "PBKDF2WITHHMACSHA512", "SHA512", "SHA-512":
		return sha512.New
	case "PBKDF2WITHHMACSHA1", "SHA1", "SHA-1":
		return sha1.New
	case "PBKDF2WITHHMACSHA256", "SHA256", "SHA-256", "":
		return sha256.New
	default:
		return sha256.New
	}
}

// Encode implements [core.PasswordEncoder].
func (this *Pbkdf2PasswordEncoder) Encode(password []byte) ([]byte, error) {
	saltLength := this.saltLength
	if saltLength <= 0 {
		saltLength = Pbkdf2DefaultSaltLength
	}
	iterations := this.iterations
	if iterations <= 0 {
		iterations = Pbkdf2DefaultIterations
	}
	keyLength := this.keyLength
	if keyLength <= 0 {
		keyLength = Pbkdf2DefaultKeyLength
	}

	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return []byte(""), err
	}

	saltAndSecret := append([]byte(nil), salt...)
	if len(this.secret) > 0 {
		saltAndSecret = append(saltAndSecret, this.secret...)
	}

	hashFunc := getPbkdf2HashFunc(this.algorithm)
	derived := pbkdf2.Key(password, saltAndSecret, iterations, keyLength, hashFunc)

	// Spring Security format: salt concatenated with derived hash
	combined := append(salt, derived...)

	var result string
	if this.encodeHashAsBase64 {
		result = base64.StdEncoding.EncodeToString(combined)
	} else {
		result = hex.EncodeToString(combined)
	}

	return []byte(result), nil
}

// Matches implements [core.PasswordEncoder].
func (this *Pbkdf2PasswordEncoder) Matches(password, encoded []byte) bool {
	encodedStr := string(encoded)

	saltLength := this.saltLength
	if saltLength <= 0 {
		saltLength = Pbkdf2DefaultSaltLength
	}
	iterations := this.iterations
	if iterations <= 0 {
		iterations = Pbkdf2DefaultIterations
	}
	hashFunc := getPbkdf2HashFunc(this.algorithm)

	// Check if modular crypt / Django or PHC format: e.g. pbkdf2_sha256$... or $pbkdf2-sha256$...
	if strings.Contains(encodedStr, "$") {
		parts := strings.Split(encodedStr, "$")
		// Django format: pbkdf2_sha256$iterations$salt$hash
		if len(parts) == 4 && strings.HasPrefix(parts[0], "pbkdf2_") {
			iter, err := strconv.Atoi(parts[1])
			if err != nil {
				return false
			}
			var hFunc func() hash.Hash
			switch parts[0] {
			case "pbkdf2_sha256":
				hFunc = sha256.New
			case "pbkdf2_sha512":
				hFunc = sha512.New
			case "pbkdf2_sha1":
				hFunc = sha1.New
			default:
				hFunc = hashFunc
			}
			salt := []byte(parts[2])
			expectedHash, err := decodeBase64(parts[3])
			if err != nil {
				return false
			}
			saltAndSecret := append([]byte(nil), salt...)
			if len(this.secret) > 0 {
				saltAndSecret = append(saltAndSecret, this.secret...)
			}
			computed := pbkdf2.Key(password, saltAndSecret, iter, len(expectedHash), hFunc)
			return subtle.ConstantTimeCompare(expectedHash, computed) == 1
		}

		// PHC format: $pbkdf2-sha256$i=310000$<salt>$<hash>
		if len(parts) >= 5 && strings.HasPrefix(parts[1], "pbkdf2") {
			var iter int
			for _, p := range strings.Split(parts[2], ",") {
				kv := strings.SplitN(p, "=", 2)
				if len(kv) == 2 && kv[0] == "i" {
					iter, _ = strconv.Atoi(kv[1])
				}
			}
			if iter <= 0 {
				iter = iterations
			}
			var hFunc func() hash.Hash
			if strings.Contains(parts[1], "sha512") {
				hFunc = sha512.New
			} else if strings.Contains(parts[1], "sha1") {
				hFunc = sha1.New
			} else {
				hFunc = sha256.New
			}
			salt, err := decodeBase64(parts[3])
			if err != nil {
				return false
			}
			expectedHash, err := decodeBase64(parts[4])
			if err != nil {
				return false
			}
			saltAndSecret := append([]byte(nil), salt...)
			if len(this.secret) > 0 {
				saltAndSecret = append(saltAndSecret, this.secret...)
			}
			computed := pbkdf2.Key(password, saltAndSecret, iter, len(expectedHash), hFunc)
			return subtle.ConstantTimeCompare(expectedHash, computed) == 1
		}
	}

	// Standard Spring Security format: Hex or Base64 of (salt || hash)
	var digested []byte
	var err error
	if this.encodeHashAsBase64 {
		digested, err = decodeBase64(encodedStr)
		if err != nil {
			digested, err = hex.DecodeString(encodedStr)
		}
	} else {
		digested, err = hex.DecodeString(encodedStr)
		if err != nil {
			digested, err = decodeBase64(encodedStr)
		}
	}

	if err != nil || len(digested) <= saltLength {
		return false
	}

	salt := digested[:saltLength]
	expectedHash := digested[saltLength:]

	saltAndSecret := append([]byte(nil), salt...)
	if len(this.secret) > 0 {
		saltAndSecret = append(saltAndSecret, this.secret...)
	}

	computed := pbkdf2.Key(password, saltAndSecret, iterations, len(expectedHash), hashFunc)
	if len(computed) != len(expectedHash) {
		return false
	}

	return subtle.ConstantTimeCompare(expectedHash, computed) == 1
}
