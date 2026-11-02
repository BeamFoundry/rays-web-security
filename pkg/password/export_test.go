package password

import (
	"io"
)

// SetRandReaderForTest sets randReader for testing.
func SetRandReaderForTest(r io.Reader) func() {
	orig := randReader
	randReader = r
	return func() {
		randReader = orig
	}
}
