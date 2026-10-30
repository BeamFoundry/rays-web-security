package password

import (
	. "github.com/BeamFoundry/rays-web-security/pkg/core"

	"golang.org/x/crypto/bcrypt"
)

const (
	BCryptDefaultCost     = bcrypt.DefaultCost
	BCryptDefaultStrength = BCryptDefaultCost
)

type BCryptPasswordEncoder struct {
	strength int
}

func (this BCryptPasswordEncoder) New(strength int) *BCryptPasswordEncoder {
	this.strength = strength
	return &this
}

func (this BCryptPasswordEncoder) NewDefault() *BCryptPasswordEncoder {
	return this.New(BCryptDefaultCost)
}

// Encode implements [core.PasswordEncoder].
func (this *BCryptPasswordEncoder) Encode(password []byte) ([]byte, error) {
	strength := this.strength
	if strength <= 0 {
		strength = BCryptDefaultCost
	}
	encoded, err := bcrypt.GenerateFromPassword(password, strength)
	if err != nil {
		return []byte(""), err
	}
	return encoded, nil
}

// Matches implements [core.PasswordEncoder].
func (this *BCryptPasswordEncoder) Matches(password, encoded []byte) bool {
	if err := bcrypt.CompareHashAndPassword(encoded, password); err != nil {
		return false
	}
	return true
}

var _ PasswordEncoder = &BCryptPasswordEncoder{}

type BcryptPasswordEncoder = BCryptPasswordEncoder
