package password

import (
	"bytes"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"

	"golang.org/x/crypto/bcrypt"
)

type BCryptPasswordEncoder struct {
	strength int
}

func (this BCryptPasswordEncoder) New(strength int) *BCryptPasswordEncoder {
	this.strength = strength
	return &this
}

// Encode implements [core.PasswordEncoder].
func (this *BCryptPasswordEncoder) Encode(password []byte) ([]byte, error) {
	encoded, err := bcrypt.GenerateFromPassword(password, this.strength)
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

type NoOpPasswordEncoder struct{}

func (this NoOpPasswordEncoder) New() *NoOpPasswordEncoder {
	return &this
}

// Encode implements [core.PasswordEncoder].
func (this *NoOpPasswordEncoder) Encode(password []byte) ([]byte, error) {
	return password, nil
}

// Matches implements [core.PasswordEncoder].
func (this *NoOpPasswordEncoder) Matches(password, encoded []byte) bool {
	return bytes.Equal(password, encoded)
}

var _ PasswordEncoder = &NoOpPasswordEncoder{}

type DelegatingPasswordEncoder struct {
	idToPasswordEncoder map[string]PasswordEncoder
	idForEncode         string
}

var _ PasswordEncoder = &DelegatingPasswordEncoder{}

func (this DelegatingPasswordEncoder) New(idForEncode string, idToPasswordEncoder map[string]PasswordEncoder) *DelegatingPasswordEncoder {
	this.idForEncode = idForEncode
	this.idToPasswordEncoder = idToPasswordEncoder
	return &this
}

// Encode implements [core.PasswordEncoder].
func (this *DelegatingPasswordEncoder) Encode(password []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteRune('{')
	buf.WriteString(this.idForEncode)
	buf.WriteRune('}')
	encoded, err := this.idToPasswordEncoder[this.idForEncode].Encode(password)
	if err != nil {
		return []byte(""), err
	}
	buf.Write(encoded)
	return buf.Bytes(), nil
}

// Matches implements [core.PasswordEncoder].
func (this *DelegatingPasswordEncoder) Matches(password, encoded []byte) bool {
	for id, encoder := range this.idToPasswordEncoder {
		if String(encoded).StartsWith("{" + id + "}") {
			p := String(encoded).Replace("{"+id+"}", "")
			return encoder.Matches(password, []byte(p))
		}
	}
	return false
}
