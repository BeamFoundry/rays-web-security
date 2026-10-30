package certs_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays-web-security/pkg/certs"
)

var _ = Describe("ClientCertificateProvider", func() {
	It("returns nil, nil when no fields are set", func() {
		provider := &ClientCertificateProvider{}
		cfg, err := provider.ProvideClientTLS()
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).To(BeNil())
	})

	It("uses TLS 1.2 by default and allows setting custom MinVersion", func() {
		provider := &ClientCertificateProvider{
			RootCertificates: "testdata/pki/cacert.pem",
		}
		cfg, err := provider.ProvideClientTLS()
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.MinVersion).To(Equal(uint16(tls.VersionTLS12)))

		provider13 := &ClientCertificateProvider{
			RootCertificates: "testdata/pki/cacert.pem",
			TLSMinVersion:    tls.VersionTLS13,
		}
		cfg13, err := provider13.ProvideClientTLS()
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg13.MinVersion).To(Equal(uint16(tls.VersionTLS13)))
	})

	It("rejects unsupported TLSMinVersion", func() {
		provider := &ClientCertificateProvider{
			RootCertificates: "testdata/pki/cacert.pem",
			TLSMinVersion:    tls.VersionTLS10,
		}
		cfg, err := provider.ProvideClientTLS()
		Expect(err).To(MatchError(ErrUnsupportedTLSVersion))
		Expect(cfg).To(BeNil())
	})

	It("returns error when RootCertificates file does not exist", func() {
		provider := &ClientCertificateProvider{
			RootCertificates: "does-not-exist.pem",
		}
		cfg, err := provider.ProvideClientTLS()
		Expect(err).To(HaveOccurred())
		Expect(cfg).To(BeNil())
	})

	It("returns error when RootCertificates contains invalid PEM data", func() {
		provider := &ClientCertificateProvider{
			RootCertificates: "invalid pem content",
		}
		cfg, err := provider.ProvideClientTLS()
		Expect(err).To(HaveOccurred())
		Expect(cfg).To(BeNil())
	})

	It("returns error when RootCertificates file contains invalid PEM data", func() {
		tmpDir := GinkgoT().TempDir()
		badPath := filepath.Join(tmpDir, "invalid.pem")
		err := os.WriteFile(badPath, []byte("not a pem"), 0o600)
		Expect(err).NotTo(HaveOccurred())

		provider := &ClientCertificateProvider{
			RootCertificates: badPath,
		}
		cfg, err := provider.ProvideClientTLS()
		Expect(err).To(HaveOccurred())
		Expect(cfg).To(BeNil())
	})

	It("loads RootCertificates from file", func() {
		provider := &ClientCertificateProvider{
			RootCertificates: "testdata/pki/cacert.pem",
		}
		cfg, err := provider.ProvideClientTLS()
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).NotTo(BeNil())
		Expect(cfg.RootCAs).NotTo(BeNil())
	})

	It("loads RootCertificates from PEM string content", func() {
		content, err := os.ReadFile("testdata/pki/cacert.pem")
		Expect(err).NotTo(HaveOccurred())

		provider := &ClientCertificateProvider{
			RootCertificates: string(content),
		}
		cfg, err := provider.ProvideClientTLS()
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).NotTo(BeNil())
		Expect(cfg.RootCAs).NotTo(BeNil())
	})

	It("loads Certificate from file", func() {
		provider := &ClientCertificateProvider{
			Certificate: "testdata/pki/intermediate/client/fullchain.pem",
		}
		cfg, err := provider.ProvideClientTLS()
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).NotTo(BeNil())
		Expect(cfg.Certificates).To(HaveLen(1))
	})

	It("loads Certificate from PEM string content", func() {
		content, err := os.ReadFile("testdata/pki/intermediate/client/fullchain.pem")
		Expect(err).NotTo(HaveOccurred())

		provider := &ClientCertificateProvider{
			Certificate: string(content),
		}
		cfg, err := provider.ProvideClientTLS()
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).NotTo(BeNil())
		Expect(cfg.Certificates).To(HaveLen(1))
	})

	It("returns error for non-existent certificate file", func() {
		provider := &ClientCertificateProvider{
			Certificate: "does-not-exist.pem",
		}
		cfg, err := provider.ProvideClientTLS()
		Expect(err).To(HaveOccurred())
		Expect(cfg).To(BeNil())
	})

	It("returns error for invalid PEM certificate content", func() {
		provider := &ClientCertificateProvider{
			Certificate: "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",
		}
		cfg, err := provider.ProvideClientTLS()
		Expect(err).To(HaveOccurred())
		Expect(cfg).To(BeNil())
	})

	It("returns error when Certificate PEM has no private key", func() {
		cacert, err := os.ReadFile("testdata/pki/cacert.pem")
		Expect(err).NotTo(HaveOccurred())

		provider := &ClientCertificateProvider{
			Certificate: string(cacert),
		}
		cfg, err := provider.ProvideClientTLS()
		Expect(err).To(HaveOccurred())
		Expect(cfg).To(BeNil())
	})

	It("returns error when RootCertificates has no CERTIFICATE blocks", func() {
		key, err := os.ReadFile("testdata/pki/intermediate/server/key.pem")
		Expect(err).NotTo(HaveOccurred())

		provider := &ClientCertificateProvider{
			RootCertificates: string(key),
		}
		cfg, err := provider.ProvideClientTLS()
		Expect(err).To(MatchError(ErrAppendRootCertificates))
		Expect(cfg).To(BeNil())
	})

	It("handles systemCertPool failure", func() {
		cleanup := SetSystemCertPoolForTest(func() (*x509.CertPool, error) {
			return nil, errors.New("system cert pool failure")
		})
		defer cleanup()

		provider := &ClientCertificateProvider{
			IncludeSystemCertificates: true,
		}
		cfg, err := provider.ProvideClientTLS()
		Expect(err).To(HaveOccurred())
		Expect(cfg).To(BeNil())

		providerCert := &ClientCertificateProvider{
			IncludeSystemCertificates: true,
			Certificate:               "testdata/pki/intermediate/client/fullchain.pem",
		}
		cfg, err = providerCert.ProvideClientTLS()
		Expect(err).To(HaveOccurred())
		Expect(cfg).To(BeNil())

		providerRoot := &ClientCertificateProvider{
			IncludeSystemCertificates: true,
			RootCertificates:          "testdata/pki/cacert.pem",
		}
		cfg, err = providerRoot.ProvideClientTLS()
		Expect(err).To(HaveOccurred())
		Expect(cfg).To(BeNil())
	})

	It("supports IncludeSystemCertificates", func() {
		provider := &ClientCertificateProvider{
			IncludeSystemCertificates: true,
		}
		cfg, err := provider.ProvideClientTLS()
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).NotTo(BeNil())
		Expect(cfg.RootCAs).NotTo(BeNil())
	})
})
