package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"

	"golang.org/x/crypto/argon2"
)

const (
	Argon2DefaultSaltLength  = 16
	Argon2DefaultHashLength  = 32
	Argon2DefaultParallelism = 1
	Argon2DefaultMemory      = 1 << 14 // 16384 KiB (16 MiB)
	Argon2DefaultIterations  = 2
)

// Argon2PasswordEncoder implements [core.PasswordEncoder] using the Argon2 hashing algorithm
// (specifically Argon2id by default, adhering to RFC 9106 and the PHC string format).
type Argon2PasswordEncoder struct {
	iterations  uint32
	memory      uint32
	parallelism uint8
	keyLength   uint32
	saltLength  int
}

var _ PasswordEncoder = &Argon2PasswordEncoder{}

// New constructs an Argon2PasswordEncoder with custom parameters.
func (this Argon2PasswordEncoder) New(iterations, memory uint32, parallelism uint8, keyLength uint32, saltLength int) *Argon2PasswordEncoder {
	this.iterations = iterations
	this.memory = memory
	this.parallelism = parallelism
	this.keyLength = keyLength
	this.saltLength = saltLength
	return &this
}

// NewDefault constructs an Argon2PasswordEncoder with recommended defaults
// matching Spring Security 5.8+ defaults (iterations=2, memory=16384 KiB, parallelism=1, keyLength=32, saltLength=16).
func (this Argon2PasswordEncoder) NewDefault() *Argon2PasswordEncoder {
	return this.New(
		Argon2DefaultIterations,
		Argon2DefaultMemory,
		Argon2DefaultParallelism,
		Argon2DefaultHashLength,
		Argon2DefaultSaltLength,
	)
}

// Encode implements [core.PasswordEncoder].
func (this *Argon2PasswordEncoder) Encode(password []byte) ([]byte, error) {
	saltLength := this.saltLength
	if saltLength <= 0 {
		saltLength = Argon2DefaultSaltLength
	}
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return []byte(""), err
	}

	iterations := this.iterations
	if iterations == 0 {
		iterations = Argon2DefaultIterations
	}
	memory := this.memory
	if memory == 0 {
		memory = Argon2DefaultMemory
	}
	parallelism := this.parallelism
	if parallelism == 0 {
		parallelism = Argon2DefaultParallelism
	}
	keyLength := this.keyLength
	if keyLength == 0 {
		keyLength = Argon2DefaultHashLength
	}

	hash := argon2.IDKey(password, salt, iterations, memory, parallelism, keyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, iterations, parallelism, b64Salt, b64Hash)

	return []byte(encoded), nil
}

// Matches implements [core.PasswordEncoder].
func (this *Argon2PasswordEncoder) Matches(password, encoded []byte) bool {
	parts := strings.Split(string(encoded), "$")
	// Expected parts: ["", "argon2id"|"argon2i", ("v=19"), "m=...,t=...,p=...", salt, hash]
	if len(parts) < 5 {
		return false
	}
	idx := 1
	algoType := parts[idx]
	if algoType != "argon2id" && algoType != "argon2i" && algoType != "argon2d" {
		return false
	}
	idx++

	if strings.HasPrefix(parts[idx], "v=") {
		idx++
	}
	if idx >= len(parts)-2 {
		return false
	}

	paramParts := strings.Split(parts[idx], ",")
	idx++

	var memory, iterations uint32
	var parallelism uint8
	var hasM, hasT, hasP bool

	for _, p := range paramParts {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		val, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			return false
		}
		switch kv[0] {
		case "m":
			memory = uint32(val)
			hasM = true
		case "t":
			iterations = uint32(val)
			hasT = true
		case "p":
			parallelism = uint8(val)
			hasP = true
		}
	}

	if !hasM || !hasT || !hasP || idx != len(parts)-2 {
		return false
	}

	salt, err := decodeBase64(parts[idx])
	if err != nil {
		return false
	}
	expectedHash, err := decodeBase64(parts[idx+1])
	if err != nil {
		return false
	}

	var computedHash []byte
	if algoType == "argon2i" {
		computedHash = argon2.Key(password, salt, iterations, memory, parallelism, uint32(len(expectedHash)))
	} else {
		computedHash = argon2.IDKey(password, salt, iterations, memory, parallelism, uint32(len(expectedHash)))
	}

	if len(computedHash) != len(expectedHash) {
		return false
	}
	return subtle.ConstantTimeCompare(expectedHash, computedHash) == 1
}

func decodeBase64(s string) ([]byte, error) {
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}
