package password

import (
	"crypto"
	"crypto/sha1" // #nosec G505 - PBKDF2 with SHA-1 is supported for Spring Security legacy compatibility
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
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
	Pbkdf2MaxIterations     = 5000000
)

// Pbkdf2PasswordEncoder implements [core.PasswordEncoder] using the PBKDF2 key derivation function.
// It defaults to PBKDF2 with HMAC-SHA256 and Hex encoding, compatible with Spring Security's Pbkdf2PasswordEncoder.
type Pbkdf2PasswordEncoder struct {
	algorithm          string
	secret             []byte
	saltLength         int
	iterations         int
	keyLength          int
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

func getPbkdf2HashFunc(algorithm string) (func() hash.Hash, error) {
	trimmed := strings.TrimSpace(algorithm)
	if trimmed == "" {
		return sha256.New, nil
	}
	sha512Str := crypto.SHA512.String()
	sha1Str := crypto.SHA1.String()
	sha256Str := crypto.SHA256.String()

	upper := strings.ToUpper(trimmed)
	switch upper {
	case "PBKDF2WITHHMACSHA512", "SHA512", sha512Str:
		return sha512.New, nil
	case "PBKDF2WITHHMACSHA1", "SHA1", sha1Str:
		return sha1.New, nil
	case "PBKDF2WITHHMACSHA256", "SHA256", sha256Str:
		return sha256.New, nil
	default:
		return nil, fmt.Errorf("unsupported PBKDF2 algorithm: %s", algorithm)
	}
}

// Encode implements [core.PasswordEncoder].
func (this *Pbkdf2PasswordEncoder) Encode(password []byte) ([]byte, error) {
	hashFunc, err := getPbkdf2HashFunc(this.algorithm)
	if err != nil {
		return []byte(""), err
	}

	saltLength := this.saltLength
	if saltLength <= 0 {
		saltLength = Pbkdf2DefaultSaltLength
	}
	iterations := this.iterations
	if iterations <= 0 {
		iterations = Pbkdf2DefaultIterations
	}
	if iterations > Pbkdf2MaxIterations {
		return []byte(""), fmt.Errorf("iterations %d exceeds maximum allowed %d", iterations, Pbkdf2MaxIterations)
	}
	keyLength := this.keyLength
	if keyLength <= 0 {
		keyLength = Pbkdf2DefaultKeyLength
	}

	salt := make([]byte, saltLength)
	if _, err := randReader.Read(salt); err != nil {
		return []byte(""), err
	}

	saltAndSecret := append([]byte(nil), salt...)
	if len(this.secret) > 0 {
		saltAndSecret = append(saltAndSecret, this.secret...)
	}

	derived := pbkdf2.Key(password, saltAndSecret, iterations, keyLength, hashFunc)

	// Spring Security format: salt concatenated with derived hash
	combined := make([]byte, 0, len(salt)+len(derived))
	combined = append(combined, salt...)
	combined = append(combined, derived...)

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

	hashFunc, err := getPbkdf2HashFunc(this.algorithm)
	if err != nil {
		return false
	}

	// Check if modular crypt / Django or PHC format: e.g. pbkdf2_sha256$... or $pbkdf2-sha256$...
	if strings.Contains(encodedStr, "$") {
		parts := strings.Split(encodedStr, "$")
		// Django format: pbkdf2_sha256$iterations$salt$hash
		if len(parts) == 4 && strings.HasPrefix(parts[0], "pbkdf2_") {
			var iter int
			var parseErr error
			iter, parseErr = strconv.Atoi(parts[1])
			if parseErr != nil || iter <= 0 || iter > Pbkdf2MaxIterations {
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
				return false
			}
			salt := []byte(parts[2])
			if len(salt) == 0 {
				return false
			}
			expectedHash, decodeErr := decodeBase64(parts[3])
			if decodeErr != nil || len(expectedHash) == 0 {
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
			var hasIter bool
			for _, p := range strings.Split(parts[2], ",") {
				kv := strings.SplitN(p, "=", 2)
				if len(kv) == 2 && kv[0] == "i" {
					var parseErr error
					iter, parseErr = strconv.Atoi(kv[1])
					if parseErr != nil {
						return false
					}
					hasIter = true
				}
			}
			if !hasIter || iter <= 0 || iter > Pbkdf2MaxIterations {
				return false
			}
			var hFunc func() hash.Hash
			switch parts[1] {
			case "pbkdf2-sha512":
				hFunc = sha512.New
			case "pbkdf2-sha256":
				hFunc = sha256.New
			case "pbkdf2-sha1":
				hFunc = sha1.New
			case "pbkdf2":
				hFunc = hashFunc
			default:
				return false
			}
			salt, saltErr := decodeBase64(parts[3])
			if saltErr != nil || len(salt) == 0 {
				return false
			}
			expectedHash, hashErr := decodeBase64(parts[4])
			if hashErr != nil || len(expectedHash) == 0 {
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
	if iterations <= 0 || iterations > Pbkdf2MaxIterations {
		return false
	}

	checkCandidate := func(candidate []byte) bool {
		if len(candidate) <= saltLength {
			return false
		}

		salt := candidate[:saltLength]
		expectedHash := candidate[saltLength:]

		saltAndSecret := append([]byte(nil), salt...)
		if len(this.secret) > 0 {
			saltAndSecret = append(saltAndSecret, this.secret...)
		}

		computed := pbkdf2.Key(password, saltAndSecret, iterations, len(expectedHash), hashFunc)
		return subtle.ConstantTimeCompare(expectedHash, computed) == 1
	}

	var primaryDecoder, secondaryDecoder func(string) ([]byte, error)
	if this.encodeHashAsBase64 {
		primaryDecoder = decodeBase64
		secondaryDecoder = hex.DecodeString
	} else {
		primaryDecoder = hex.DecodeString
		secondaryDecoder = decodeBase64
	}

	if candidate, err := primaryDecoder(encodedStr); err == nil && checkCandidate(candidate) {
		return true
	}
	if candidate, err := secondaryDecoder(encodedStr); err == nil && checkCandidate(candidate) {
		return true
	}

	return false
}
