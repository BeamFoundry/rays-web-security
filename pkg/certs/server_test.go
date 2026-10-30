package certs_test

import (
	"crypto/tls"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/acme/autocert"

	. "github.com/BeamFoundry/rays-web-security/pkg/certs"
)

var _ = Describe("Server Providers", func() {
	Context("ServerCertificateProvider", func() {
		It("validates TLSMinVersion", func() {
			for _, invalidVer := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
				provider := &ServerCertificateProvider{
					Certificate:   "testdata/pki/intermediate/server/fullchain.pem",
					TLSMinVersion: invalidVer,
				}
				cfg, err := provider.ProvideServerTLS()
				Expect(err).To(MatchError(ErrUnsupportedTLSVersion))
				Expect(cfg).To(BeNil())
			}

			for _, validVer := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				provider := &ServerCertificateProvider{
					Certificate:   "testdata/pki/intermediate/server/fullchain.pem",
					TLSMinVersion: validVer,
				}
				cfg, err := provider.ProvideServerTLS()
				Expect(err).NotTo(HaveOccurred())
				Expect(cfg).NotTo(BeNil())
				Expect(cfg.MinVersion).To(Equal(validVer))
			}

			// Default version is TLS 1.2
			provider := &ServerCertificateProvider{
				Certificate: "testdata/pki/intermediate/server/fullchain.pem",
			}
			cfg, err := provider.ProvideServerTLS()
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).NotTo(BeNil())
			Expect(cfg.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
		})

		It("returns nil, nil when no certificate is provided", func() {
			provider := &ServerCertificateProvider{}
			cfg, err := provider.ProvideServerTLS()
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).To(BeNil())
		})

		It("loads certificate from file", func() {
			provider := &ServerCertificateProvider{
				Certificate: "testdata/pki/intermediate/server/fullchain.pem",
			}
			cfg, err := provider.ProvideServerTLS()
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).NotTo(BeNil())
			Expect(cfg.Certificates).To(HaveLen(1))
		})

		It("loads certificate from PEM string content", func() {
			content, err := os.ReadFile("testdata/pki/intermediate/server/fullchain.pem")
			Expect(err).NotTo(HaveOccurred())

			provider := &ServerCertificateProvider{
				Certificate: string(content),
			}
			cfg, err := provider.ProvideServerTLS()
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).NotTo(BeNil())
			Expect(cfg.Certificates).To(HaveLen(1))
		})

		It("loads certificate from deprecated CertFile and CertKeyFile", func() {
			provider := &ServerCertificateProvider{
				CertFile:    "testdata/pki/intermediate/server/cert.pem",
				CertKeyFile: "testdata/pki/intermediate/server/key.pem",
			}
			cfg, err := provider.ProvideServerTLS()
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).NotTo(BeNil())
			Expect(cfg.Certificates).To(HaveLen(1))
		})

		It("returns error for non-existent certificate file", func() {
			provider := &ServerCertificateProvider{
				Certificate: "testdata/non-existent.pem",
			}
			cfg, err := provider.ProvideServerTLS()
			Expect(err).To(HaveOccurred())
			Expect(cfg).To(BeNil())
		})

		It("returns error for invalid PEM certificate content", func() {
			provider := &ServerCertificateProvider{
				Certificate: "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",
			}
			cfg, err := provider.ProvideServerTLS()
			Expect(err).To(HaveOccurred())
			Expect(cfg).To(BeNil())
		})

		It("returns error for invalid CertFile / CertKeyFile paths", func() {
			provider := &ServerCertificateProvider{
				CertFile:    "testdata/non-existent.pem",
				CertKeyFile: "testdata/pki/intermediate/server/key.pem",
			}
			cfg, err := provider.ProvideServerTLS()
			Expect(err).To(HaveOccurred())
			Expect(cfg).To(BeNil())
		})

		It("returns error when only CertFile is provided", func() {
			provider := &ServerCertificateProvider{
				CertFile: "testdata/pki/intermediate/server/cert.pem",
			}
			cfg, err := provider.ProvideServerTLS()
			Expect(err).To(HaveOccurred())
			Expect(cfg).To(BeNil())
		})

		It("returns error when only CertKeyFile is provided", func() {
			provider := &ServerCertificateProvider{
				CertKeyFile: "testdata/pki/intermediate/server/key.pem",
			}
			cfg, err := provider.ProvideServerTLS()
			Expect(err).To(HaveOccurred())
			Expect(cfg).To(BeNil())
		})

		It("returns error when Certificate PEM does not contain private key", func() {
			cacert, err := os.ReadFile("testdata/pki/cacert.pem")
			Expect(err).NotTo(HaveOccurred())

			provider := &ServerCertificateProvider{
				Certificate: string(cacert),
			}
			cfg, err := provider.ProvideServerTLS()
			Expect(err).To(HaveOccurred())
			Expect(cfg).To(BeNil())
		})
	})

	Context("ACMECertificateProvider", func() {
		It("validates TLSMinVersion", func() {
			provider := &ACMECertificateProvider{
				TLSMinVersion: tls.VersionTLS10,
			}
			cfg, err := provider.ProvideServerTLS()
			Expect(err).To(MatchError(ErrUnsupportedTLSVersion))
			Expect(cfg).To(BeNil())
		})

		It("returns nil, nil when AutoCertManager is nil", func() {
			provider := &ACMECertificateProvider{}
			cfg, err := provider.ProvideServerTLS()
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).To(BeNil())
		})

		It("configures tls.Config when AutoCertManager is provided", func() {
			mgr := &autocert.Manager{}
			provider := &ACMECertificateProvider{
				AutoCertManager: mgr,
				TLSMinVersion:   tls.VersionTLS13,
			}
			cfg, err := provider.ProvideServerTLS()
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).NotTo(BeNil())
			Expect(cfg.MinVersion).To(Equal(uint16(tls.VersionTLS13)))
			Expect(cfg.GetCertificate).NotTo(BeNil())
			Expect(cfg.NextProtos).To(Equal([]string{"http/1.1", "acme-tls/1"}))
		})
	})
})
