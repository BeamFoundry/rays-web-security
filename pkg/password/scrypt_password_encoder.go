package password

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"strings"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"

	"golang.org/x/crypto/scrypt"
)

const (
	SCryptDefaultCpuCost     = 65536 // 2^16 (N)
	SCryptDefaultMemoryCost  = 8     // (r)
	SCryptDefaultParallelism = 1     // (p)
	SCryptDefaultKeyLength   = 32    // (dkLen)
	SCryptDefaultSaltLength  = 16
	SCryptMaxCpuCost         = 1 << 20 // 1048576
	SCryptMaxLn              = 20
	SCryptMaxMemoryCost      = 64
	SCryptMaxParallelism     = 64
	SCryptMaxNr              = 1 << 20 // 1048576
)

// SCryptPasswordEncoder implements [core.PasswordEncoder] using the SCrypt key derivation function.
// It formats and parses hashes compatible with Spring Security's SCrypt format ($<hex_params>$<salt>$<derived>).
type SCryptPasswordEncoder struct {
	cpuCost     int
	memoryCost  int
	parallelism int
	keyLength   int
	saltLength  int
}

var _ PasswordEncoder = &SCryptPasswordEncoder{}

type ScryptPasswordEncoder = SCryptPasswordEncoder

// New constructs an SCryptPasswordEncoder with custom parameters.
func (this SCryptPasswordEncoder) New(cpuCost, memoryCost, parallelism, keyLength, saltLength int) *SCryptPasswordEncoder {
	this.cpuCost = cpuCost
	this.memoryCost = memoryCost
	this.parallelism = parallelism
	this.keyLength = keyLength
	this.saltLength = saltLength
	return &this
}

// NewDefault constructs an SCryptPasswordEncoder with recommended defaults
// matching Spring Security 5.8+ defaults (cpuCost=65536, memoryCost=8, parallelism=1, keyLength=32, saltLength=16).
func (this SCryptPasswordEncoder) NewDefault() *SCryptPasswordEncoder {
	return this.New(
		SCryptDefaultCpuCost,
		SCryptDefaultMemoryCost,
		SCryptDefaultParallelism,
		SCryptDefaultKeyLength,
		SCryptDefaultSaltLength,
	)
}

// Encode implements [core.PasswordEncoder].
func (this *SCryptPasswordEncoder) Encode(password []byte) ([]byte, error) {
	cpuCost := this.cpuCost
	if cpuCost <= 0 {
		cpuCost = SCryptDefaultCpuCost
	}
	memoryCost := this.memoryCost
	if memoryCost <= 0 {
		memoryCost = SCryptDefaultMemoryCost
	}
	parallelism := this.parallelism
	if parallelism <= 0 {
		parallelism = SCryptDefaultParallelism
	}
	keyLength := this.keyLength
	if keyLength <= 0 {
		keyLength = SCryptDefaultKeyLength
	}
	saltLength := this.saltLength
	if saltLength <= 0 {
		saltLength = SCryptDefaultSaltLength
	}

	if cpuCost > SCryptMaxCpuCost || memoryCost > SCryptMaxMemoryCost || parallelism > SCryptMaxParallelism || cpuCost > SCryptMaxNr/memoryCost {
		return []byte(""), fmt.Errorf("scrypt parameters exceed maximum bounds (cpuCost: %d, memoryCost: %d, parallelism: %d)", cpuCost, memoryCost, parallelism)
	}

	salt := make([]byte, saltLength)
	if _, err := randReader.Read(salt); err != nil {
		return []byte(""), err
	}

	derived, err := scrypt.Key(password, salt, cpuCost, memoryCost, parallelism, keyLength)
	if err != nil {
		return []byte(""), err
	}

	log2N := int(math.Round(math.Log2(float64(cpuCost))))
	params := (log2N << 16) | (memoryCost << 8) | parallelism

	b64Salt := base64.StdEncoding.EncodeToString(salt)
	b64Derived := base64.StdEncoding.EncodeToString(derived)

	encoded := fmt.Sprintf("$%x$%s$%s", params, b64Salt, b64Derived)
	return []byte(encoded), nil
}

// Matches implements [core.PasswordEncoder].
func (this *SCryptPasswordEncoder) Matches(password, encoded []byte) bool {
	parts := strings.Split(string(encoded), "$")

	// Spring Security format: ["", "<hex_params>", "<b64_salt>", "<b64_derived>"]
	if len(parts) == 4 && parts[0] == "" {
		params, err := strconv.ParseInt(parts[1], 16, 64)
		if err != nil {
			return false
		}
		salt, err := decodeBase64(parts[2])
		if err != nil || len(salt) == 0 {
			return false
		}
		derived, err := decodeBase64(parts[3])
		if err != nil || len(derived) == 0 {
			return false
		}

		log2N := int((params >> 16) & 0xffff)
		if log2N < 1 || log2N > SCryptMaxLn {
			return false
		}
		cpuCost := 1 << log2N
		memoryCost := int((params >> 8) & 0xff)
		parallelism := int(params & 0xff)

		if cpuCost <= 1 || cpuCost > SCryptMaxCpuCost || memoryCost < 1 || memoryCost > SCryptMaxMemoryCost || parallelism < 1 || parallelism > SCryptMaxParallelism || cpuCost > SCryptMaxNr/memoryCost {
			return false
		}

		generated, _ := scrypt.Key(password, salt, cpuCost, memoryCost, parallelism, len(derived)) //nolint:errcheck // parameters are validated above
		return subtle.ConstantTimeCompare(derived, generated) == 1
	}

	// PHC format: ["", "scrypt", "ln=16,r=8,p=1", "<salt>", "<hash>"]
	if len(parts) >= 5 && parts[1] == "scrypt" {
		paramParts := strings.Split(parts[2], ",")
		var cpuCost, memoryCost, parallelism int
		for _, p := range paramParts {
			kv := strings.SplitN(p, "=", 2)
			if len(kv) != 2 {
				continue
			}
			val, err := strconv.Atoi(kv[1])
			if err != nil {
				return false
			}
			switch kv[0] {
			case "ln":
				if val < 1 || val > SCryptMaxLn {
					return false
				}
				cpuCost = 1 << val
			case "N":
				if val <= 1 || val > SCryptMaxCpuCost || (val&(val-1)) != 0 {
					return false
				}
				cpuCost = val
			case "r":
				if val < 1 || val > SCryptMaxMemoryCost {
					return false
				}
				memoryCost = val
			case "p":
				if val < 1 || val > SCryptMaxParallelism {
					return false
				}
				parallelism = val
			default:
				// Ignore unrecognized parameters
			}
		}
		if cpuCost <= 1 || cpuCost > SCryptMaxCpuCost || memoryCost < 1 || memoryCost > SCryptMaxMemoryCost || parallelism < 1 || parallelism > SCryptMaxParallelism || cpuCost > SCryptMaxNr/memoryCost {
			return false
		}

		salt, err := decodeBase64(parts[3])
		if err != nil || len(salt) == 0 {
			return false
		}
		derived, err := decodeBase64(parts[4])
		if err != nil || len(derived) == 0 {
			return false
		}

		generated, _ := scrypt.Key(password, salt, cpuCost, memoryCost, parallelism, len(derived)) //nolint:errcheck // parameters are validated above
		return subtle.ConstantTimeCompare(derived, generated) == 1
	}

	return false
}
