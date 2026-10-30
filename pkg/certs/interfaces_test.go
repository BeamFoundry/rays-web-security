package certs_test

import (
	"crypto/tls"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays-web-security/pkg/certs"
)

type dummyCustomizer struct {
	err error
}

func (d *dummyCustomizer) CustomizeServerTLS(_ *tls.Config) error {
	return d.err
}

type dummyServerProvider struct {
	cfg *tls.Config
	err error
}

func (d *dummyServerProvider) ProvideServerTLS() (*tls.Config, error) {
	return d.cfg, d.err
}

type dummyClientTLSProvider struct {
	cfg *tls.Config
	err error
}

func (d *dummyClientTLSProvider) ProvideClientTLS() (*tls.Config, error) {
	return d.cfg, d.err
}

var _ = Describe("Configure Helpers", func() {
	Context("ConfigureServerTLS", func() {
		It("returns nil, nil when provider is nil", func() {
			cfg, err := ConfigureServerTLS(nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).To(BeNil())
		})

		It("returns error when provider returns error", func() {
			expectedErr := errors.New("provider error")
			cfg, err := ConfigureServerTLS(&dummyServerProvider{err: expectedErr})
			Expect(err).To(MatchError(expectedErr))
			Expect(cfg).To(BeNil())
		})

		It("returns nil, nil when provider returns nil config without error", func() {
			cfg, err := ConfigureServerTLS(&dummyServerProvider{})
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).To(BeNil())
		})

		It("applies customizers to provided config", func() {
			serverProv := &ServerCertificateProvider{
				Certificate: "testdata/pki/intermediate/server/fullchain.pem",
			}
			customizer := &MutualTLSCustomizer{
				Certificate: "testdata/pki/intermediate/cacert.pem",
			}
			cfg, err := ConfigureServerTLS(serverProv, customizer)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).NotTo(BeNil())
			Expect(cfg.ClientAuth).To(Equal(tls.RequireAndVerifyClientCert))
		})

		It("returns error when customizer fails", func() {
			customizerErr := errors.New("customizer failed")
			serverProv := &ServerCertificateProvider{
				Certificate: "testdata/pki/intermediate/server/fullchain.pem",
			}
			cfg, err := ConfigureServerTLS(serverProv, &dummyCustomizer{err: customizerErr})
			Expect(err).To(MatchError(customizerErr))
			Expect(cfg).To(BeNil())
		})
	})

	Context("ConfigureClientTLS", func() {
		It("returns nil, nil when provider is nil", func() {
			cfg, err := ConfigureClientTLS(nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).To(BeNil())
		})

		It("returns config when provider is set", func() {
			clientProv := &ClientCertificateProvider{
				RootCertificates: "testdata/pki/cacert.pem",
			}
			cfg, err := ConfigureClientTLS(clientProv)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).NotTo(BeNil())
			Expect(cfg.RootCAs).NotTo(BeNil())
		})
	})
})
