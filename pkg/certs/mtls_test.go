package certs_test

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/go-resty/resty/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays-web-security/pkg/certs"
)

func startTLSServer(cfg *tls.Config) (addr string, cleanup func()) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("Hello"))
		Expect(err).NotTo(HaveOccurred())
	})

	ts := httptest.NewUnstartedServer(mux)
	ts.TLS = cfg
	ts.StartTLS()

	return ts.Listener.Addr().String(), ts.Close
}

func sendRequest(provider ClientTLSProvider, targetURL string) (*resty.Response, error) {
	client := resty.New()
	if provider != nil {
		tlsConfig, err := provider.ProvideClientTLS()
		if err != nil {
			return nil, err
		}
		client.SetTLSClientConfig(tlsConfig)
	}
	resp, err := client.R().Get(targetURL)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	return resp, nil
}

var _ = Describe("MutualTLSCustomizer", func() {
	It("returns nil when Certificate is empty", func() {
		customizer := &MutualTLSCustomizer{}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.ClientAuth).To(Equal(tls.NoClientCert))
		Expect(cfg.ClientCAs).To(BeNil())
	})

	It("loads CA certificate from file and configures server TLS", func() {
		customizer := &MutualTLSCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.ClientAuth).To(Equal(tls.RequireAndVerifyClientCert))
		Expect(cfg.ClientCAs).NotTo(BeNil())
	})

	It("loads CA certificate from PEM string content", func() {
		content, err := os.ReadFile("testdata/pki/intermediate/cacert.pem")
		Expect(err).NotTo(HaveOccurred())

		customizer := &MutualTLSCustomizer{
			Certificate: string(content),
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err = customizer.CustomizeServerTLS(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.ClientAuth).To(Equal(tls.RequireAndVerifyClientCert))
		Expect(cfg.ClientCAs).NotTo(BeNil())
	})

	It("returns error when certificate file does not exist", func() {
		customizer := &MutualTLSCustomizer{
			Certificate: "does-not-exist.pem",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("returns error when certificate content is invalid", func() {
		customizer := &MutualTLSCustomizer{
			Certificate: "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("returns nil certificate when PEM block is not CERTIFICATE", func() {
		customizer := &MutualTLSCustomizer{
			Certificate: "testdata/pki/intermediate/server/key.pem",
		}
		cert, err := customizer.ClientCertificate()
		Expect(err).NotTo(HaveOccurred())
		Expect(cert).To(BeNil())
	})

	It("returns error when PEM block is CERTIFICATE but content is invalid DER", func() {
		customizer := &MutualTLSCustomizer{
			Certificate: "-----BEGIN CERTIFICATE-----\naW52YWxpZA==\n-----END CERTIFICATE-----",
		}
		_, err := customizer.ClientCertificate()
		Expect(err).To(HaveOccurred())
	})

	It("enforces mTLS with authorized, expired, and missing certificates", func() {
		serverProv := &ServerCertificateProvider{
			Certificate: "testdata/pki/intermediate/server/fullchain.pem",
		}
		serverCfg, err := serverProv.ProvideServerTLS()
		Expect(err).NotTo(HaveOccurred())

		customizer := &MutualTLSCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
		}
		err = customizer.CustomizeServerTLS(serverCfg)
		Expect(err).NotTo(HaveOccurred())

		addr, cleanup := startTLSServer(serverCfg)
		defer cleanup()

		baseURL := "https://" + addr

		// 1. Authorized client cert succeeds
		authClient := &ClientCertificateProvider{
			Certificate:      "testdata/pki/intermediate/client/fullchain.pem",
			RootCertificates: "testdata/pki/cacert.pem",
		}
		resp, err := sendRequest(authClient, baseURL)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(http.StatusOK))
		Expect(resp.String()).To(Equal("Hello"))

		// 2. Expired client cert fails handshake
		expiredClient := &ClientCertificateProvider{
			Certificate:      "testdata/pki/intermediate/expired/fullchain.pem",
			RootCertificates: "testdata/pki/cacert.pem",
		}
		_, err = sendRequest(expiredClient, baseURL)
		Expect(err).To(HaveOccurred())

		// 3. Client without certificate fails handshake
		noCertClient := &ClientCertificateProvider{
			RootCertificates: "testdata/pki/cacert.pem",
		}
		_, err = sendRequest(noCertClient, baseURL)
		Expect(err).To(HaveOccurred())
	})
})
