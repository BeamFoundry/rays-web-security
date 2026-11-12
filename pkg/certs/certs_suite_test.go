package certs_test

import (
	"testing"

	_ "github.com/BeamFoundry/rays/pkg/testing"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCerts(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Certs Suite")
}
