package password

import (
	"bytes"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

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

func (this DelegatingPasswordEncoder) NewDefault() *DelegatingPasswordEncoder {
	return this.New(
		"bcrypt", map[string]PasswordEncoder{
			"bcrypt": BCryptPasswordEncoder{}.NewDefault(),
			"argon2": Argon2PasswordEncoder{}.NewDefault(),
			"pbkdf2": Pbkdf2PasswordEncoder{}.NewDefault(),
			"scrypt": SCryptPasswordEncoder{}.NewDefault(),
			"noop":   NoOpPasswordEncoder{}.New(),
		},
	)
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
		prefix := "{" + id + "}"
		if String(encoded).StartsWith(prefix) {
			p := String(encoded).Substring(len(prefix))
			return encoder.Matches(password, []byte(p))
		}
	}
	return false
}
