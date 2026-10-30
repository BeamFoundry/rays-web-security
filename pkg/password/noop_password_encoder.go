package password

import (
	"bytes"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

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
