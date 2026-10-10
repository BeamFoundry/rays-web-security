package core_test

import (
	"testing"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCore(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Core Suite")
}

var _ = Describe("Authority", func() {
	It("can be returned as a string", func() {
		Expect(Authority("ADMIN").Authority()).To(Equal("ADMIN"))
	})
})
