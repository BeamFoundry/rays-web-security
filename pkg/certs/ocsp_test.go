package certs_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ocsp"

	. "github.com/BeamFoundry/rays-web-security/pkg/certs"
)

func startHTTPSOCSPResponder(responder *OCSPResponder, serverCfg *tls.Config) (addr string, cleanup func()) {
	ts := httptest.NewUnstartedServer(responder)
	ts.TLS = serverCfg
	ts.StartTLS()

	return ts.Listener.Addr().String(), ts.Close
}

var _ = Describe("MutualTLSWithOCSPCustomizer", func() {
	It("returns nil when Certificate is empty", func() {
		customizer := &MutualTLSWithOCSPCustomizer{}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.ClientAuth).To(Equal(tls.NoClientCert))
	})

	It("returns error when Certificate path is invalid", func() {
		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate: "does-not-exist.pem",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("returns error for unsupported URL scheme", func() {
		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
			OCSPServer:  "ftp://localhost/ocsp",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("returns error when OCSPServer URL is malformed", func() {
		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
			OCSPServer:  "://invalid-url",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("returns error when HTTPS OCSP server is specified without TLSProvider", func() {
		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
			OCSPServer:  "https://localhost:8443",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(MatchError(ErrTLSProviderRequiredHTTPS))
	})

	It("returns error when TLSProvider fails during HTTPS OCSP configuration", func() {
		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
			OCSPServer:  "https://localhost:8443",
			TLSProvider: &dummyClientTLSProvider{
				err: errors.New("tls provider failed"),
			},
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("falls back to OCSPServer in CA certificate when OCSPServer is empty", func() {
		responder, err := NewOCSPResponder()
		Expect(err).NotTo(HaveOccurred())

		listener, listenErr := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:3002")
		Expect(listenErr).NotTo(HaveOccurred())

		ts := httptest.NewUnstartedServer(responder)
		ts.Listener = listener
		ts.Start()
		defer ts.Close()

		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err = customizer.CustomizeServerTLS(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.VerifyPeerCertificate).NotTo(BeNil())
	})

	It("chains with existing VerifyPeerCertificate callback", func() {
		called := false
		prevErr := errors.New("previous verification failed")
		serverProv := &ServerCertificateProvider{
			Certificate: "testdata/pki/intermediate/server/fullchain.pem",
		}
		serverCfg, err := serverProv.ProvideServerTLS()
		Expect(err).NotTo(HaveOccurred())
		serverCfg.VerifyPeerCertificate = func(_ [][]byte, _ [][]*x509.Certificate) error {
			called = true
			return prevErr
		}

		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
			OCSPServer:  "http://127.0.0.1:9999",
		}
		err = customizer.CustomizeServerTLS(serverCfg)
		Expect(err).NotTo(HaveOccurred())
		err = serverCfg.VerifyPeerCertificate(nil, nil)
		Expect(err).To(MatchError(prevErr))
		Expect(called).To(BeTrue())
	})

	It("fails peer verification when OCSP server returns 500 error", func() {
		errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "server error", http.StatusInternalServerError)
		}))
		defer errServer.Close()

		serverProv := &ServerCertificateProvider{
			Certificate: "testdata/pki/intermediate/server/fullchain.pem",
		}
		serverCfg, err := serverProv.ProvideServerTLS()
		Expect(err).NotTo(HaveOccurred())

		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
			OCSPServer:  errServer.URL,
		}
		err = customizer.CustomizeServerTLS(serverCfg)
		Expect(err).NotTo(HaveOccurred())

		addr, cleanup := startTLSServer(serverCfg)
		defer cleanup()

		authClient := &ClientCertificateProvider{
			Certificate:      "testdata/pki/intermediate/client/fullchain.pem",
			RootCertificates: "testdata/pki/cacert.pem",
		}
		_, err = sendRequest(authClient, "https://"+addr)
		Expect(err).To(HaveOccurred())
	})

	It("fails peer verification when OCSP server returns malformed response body", func() {
		errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, writeErr := w.Write([]byte("not an ocsp response"))
			Expect(writeErr).NotTo(HaveOccurred())
		}))
		defer errServer.Close()

		serverProv := &ServerCertificateProvider{
			Certificate: "testdata/pki/intermediate/server/fullchain.pem",
		}
		serverCfg, err := serverProv.ProvideServerTLS()
		Expect(err).NotTo(HaveOccurred())

		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
			OCSPServer:  errServer.URL,
		}
		err = customizer.CustomizeServerTLS(serverCfg)
		Expect(err).NotTo(HaveOccurred())

		addr, cleanup := startTLSServer(serverCfg)
		defer cleanup()

		authClient := &ClientCertificateProvider{
			Certificate:      "testdata/pki/intermediate/client/fullchain.pem",
			RootCertificates: "testdata/pki/cacert.pem",
		}
		_, err = sendRequest(authClient, "https://"+addr)
		Expect(err).To(HaveOccurred())
	})

	It("fails peer verification when OCSP server connection fails", func() {
		serverProv := &ServerCertificateProvider{
			Certificate: "testdata/pki/intermediate/server/fullchain.pem",
		}
		serverCfg, err := serverProv.ProvideServerTLS()
		Expect(err).NotTo(HaveOccurred())

		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
			OCSPServer:  "http://127.0.0.1:1",
		}
		err = customizer.CustomizeServerTLS(serverCfg)
		Expect(err).NotTo(HaveOccurred())

		clientCert, err := parseCertFile("testdata/pki/intermediate/client/cert.pem")
		Expect(err).NotTo(HaveOccurred())

		err = serverCfg.VerifyPeerCertificate(nil, [][]*x509.Certificate{{clientCert}})
		Expect(err).To(HaveOccurred())
	})

	It("handles ocsp.Unknown status for unregistered certificate serial", func() {
		responder, err := NewOCSPResponder()
		Expect(err).NotTo(HaveOccurred())

		ocspAddr, ocspCleanup := startOCSPResponder(responder)
		defer ocspCleanup()

		serverProv := &ServerCertificateProvider{
			Certificate: "testdata/pki/intermediate/server/fullchain.pem",
		}
		serverCfg, err := serverProv.ProvideServerTLS()
		Expect(err).NotTo(HaveOccurred())

		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
			OCSPServer:  "http://" + ocspAddr,
		}
		err = customizer.CustomizeServerTLS(serverCfg)
		Expect(err).NotTo(HaveOccurred())

		clientCert, err := parseCertFile("testdata/pki/intermediate/client/cert.pem")
		Expect(err).NotTo(HaveOccurred())
		clientCert.SerialNumber = big.NewInt(999999)

		err = serverCfg.VerifyPeerCertificate(nil, [][]*x509.Certificate{{clientCert}})
		Expect(err).To(MatchError(ErrCertificateUnknownOCSP))
	})

	It("handles ocspCreateRequest failure", func() {
		cleanup := SetOCSPCreateRequestForTest(func(_, _ *x509.Certificate, _ *ocsp.RequestOptions) ([]byte, error) {
			return nil, errors.New("request creation failed")
		})
		defer cleanup()

		serverProv := &ServerCertificateProvider{
			Certificate: "testdata/pki/intermediate/server/fullchain.pem",
		}
		serverCfg, err := serverProv.ProvideServerTLS()
		Expect(err).NotTo(HaveOccurred())

		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
			OCSPServer:  "http://127.0.0.1:9999",
		}
		err = customizer.CustomizeServerTLS(serverCfg)
		Expect(err).NotTo(HaveOccurred())

		clientCert, err := parseCertFile("testdata/pki/intermediate/client/cert.pem")
		Expect(err).NotTo(HaveOccurred())

		err = serverCfg.VerifyPeerCertificate(nil, [][]*x509.Certificate{{clientCert}})
		Expect(err).To(HaveOccurred())
	})

	It("verifies client certificates against OCSP responder over HTTP", func() {
		responder, err := NewOCSPResponder()
		Expect(err).NotTo(HaveOccurred())

		ocspAddr, ocspCleanup := startOCSPResponder(responder)
		defer ocspCleanup()

		serverProv := &ServerCertificateProvider{
			Certificate: "testdata/pki/intermediate/server/fullchain.pem",
		}
		serverCfg, err := serverProv.ProvideServerTLS()
		Expect(err).NotTo(HaveOccurred())

		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
			OCSPServer:  "http://" + ocspAddr,
		}
		err = customizer.CustomizeServerTLS(serverCfg)
		Expect(err).NotTo(HaveOccurred())

		addr, cleanup := startTLSServer(serverCfg)
		defer cleanup()

		baseURL := "https://" + addr

		// 1. Authorized client succeeds
		authClient := &ClientCertificateProvider{
			Certificate:      "testdata/pki/intermediate/client/fullchain.pem",
			RootCertificates: "testdata/pki/cacert.pem",
		}
		resp, err := sendRequest(authClient, baseURL)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(http.StatusOK))

		// 2. Revoked client fails handshake
		revokedClient := &ClientCertificateProvider{
			Certificate:      "testdata/pki/intermediate/revoked/fullchain.pem",
			RootCertificates: "testdata/pki/cacert.pem",
		}
		_, err = sendRequest(revokedClient, baseURL)
		Expect(err).To(HaveOccurred())
	})

	It("supports HTTPS OCSP responder when TLSProvider is provided", func() {
		responder, err := NewOCSPResponder()
		Expect(err).NotTo(HaveOccurred())

		ocspServerProv := &ServerCertificateProvider{
			Certificate: "testdata/pki/intermediate/server/fullchain.pem",
		}
		ocspServerCfg, err := ocspServerProv.ProvideServerTLS()
		Expect(err).NotTo(HaveOccurred())

		ocspAddr, ocspCleanup := startHTTPSOCSPResponder(responder, ocspServerCfg)
		defer ocspCleanup()

		serverProv := &ServerCertificateProvider{
			Certificate: "testdata/pki/intermediate/server/fullchain.pem",
		}
		serverCfg, err := serverProv.ProvideServerTLS()
		Expect(err).NotTo(HaveOccurred())

		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
			OCSPServer:  "https://" + ocspAddr,
			TLSProvider: &ClientCertificateProvider{
				RootCertificates: "testdata/pki/cacert.pem",
			},
		}
		err = customizer.CustomizeServerTLS(serverCfg)
		Expect(err).NotTo(HaveOccurred())

		addr, cleanup := startTLSServer(serverCfg)
		defer cleanup()

		baseURL := "https://" + addr

		authClient := &ClientCertificateProvider{
			Certificate:      "testdata/pki/intermediate/client/fullchain.pem",
			RootCertificates: "testdata/pki/cacert.pem",
		}
		resp, err := sendRequest(authClient, baseURL)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(http.StatusOK))
	})
})
