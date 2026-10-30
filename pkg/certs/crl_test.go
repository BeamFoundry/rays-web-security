package certs_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	. "github.com/BeamFoundry/rays/pkg/lang"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays-web-security/pkg/certs"
)

func startCRLServer(crlData []byte) (addr string, cleanup func()) {
	mux := http.NewServeMux()
	mux.HandleFunc("/crl.pem", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pkcs7-crl")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(crlData)
		Expect(err).NotTo(HaveOccurred())
	})

	ts := httptest.NewServer(mux)
	return ts.Listener.Addr().String(), ts.Close
}

func startHTTPSCRLServer(crlData []byte, serverCfg *tls.Config) (addr string, cleanup func()) {
	mux := http.NewServeMux()
	mux.HandleFunc("/crl.pem", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pkcs7-crl")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(crlData)
		Expect(err).NotTo(HaveOccurred())
	})

	ts := httptest.NewUnstartedServer(mux)
	ts.TLS = serverCfg
	ts.StartTLS()

	return ts.Listener.Addr().String(), ts.Close
}

var _ = Describe("MutualTLSWithCRLCustomizer", func() {
	It("returns nil when Certificate is empty", func() {
		customizer := &MutualTLSWithCRLCustomizer{}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.ClientAuth).To(Equal(tls.NoClientCert))
	})

	It("returns error when Certificate path is invalid", func() {
		customizer := &MutualTLSWithCRLCustomizer{
			Certificate: "does-not-exist.pem",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("returns error when CRL file does not exist", func() {
		customizer := &MutualTLSWithCRLCustomizer{
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			RevocationList: "does-not-exist.crl",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("returns error when CRL content is invalid", func() {
		customizer := &MutualTLSWithCRLCustomizer{
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			RevocationList: "-----BEGIN X509 CRL-----\ninvalid\n-----END X509 CRL-----",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("returns error when CRL has valid PEM header but invalid DER bytes", func() {
		customizer := &MutualTLSWithCRLCustomizer{
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			RevocationList: "-----BEGIN X509 CRL-----\naW52YWxpZA==\n-----END X509 CRL-----",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("returns error when CRL signature does not match CA certificate", func() {
		customizer := &MutualTLSWithCRLCustomizer{
			Certificate:    "testdata/pki/cacert.pem",
			RevocationList: "testdata/pki/intermediate/crl.pem",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("returns error when CRL file has valid PEM but is not X509 CRL", func() {
		customizer := &MutualTLSWithCRLCustomizer{
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			RevocationList: "testdata/pki/cacert.pem",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("returns error for unsupported URL scheme", func() {
		customizer := &MutualTLSWithCRLCustomizer{
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			RevocationList: "ftp://localhost/crl.pem",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("returns error when CRL fetch fails to connect", func() {
		customizer := &MutualTLSWithCRLCustomizer{
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			RevocationList: "http://127.0.0.1:1/crl.pem",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("returns error when TLSProvider fails during HTTPS CRL fetch", func() {
		customizer := &MutualTLSWithCRLCustomizer{
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			RevocationList: "https://localhost:8443/crl.pem",
			TLSProvider: &dummyClientTLSProvider{
				err: NewError("tls", "provider failed"),
			},
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("returns error when CRL fetch URL returns 404", func() {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer ts.Close()

		customizer := &MutualTLSWithCRLCustomizer{
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			RevocationList: ts.URL + "/notfound.pem",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("returns error when CRL fetch URL returns non-PEM content", func() {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("not a pem crl"))
			Expect(err).NotTo(HaveOccurred())
		}))
		defer ts.Close()

		customizer := &MutualTLSWithCRLCustomizer{
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			RevocationList: ts.URL + "/invalid.pem",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("falls back to CRLDistributionPoints in CA certificate when RevocationList is empty", func() {
		crlBytes, err := os.ReadFile("testdata/pki/intermediate/crl.pem")
		Expect(err).NotTo(HaveOccurred())

		listener, listenErr := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:3001")
		Expect(listenErr).NotTo(HaveOccurred())

		mux := http.NewServeMux()
		mux.HandleFunc("/crl.pem", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/x-pkcs7-crl")
			w.WriteHeader(http.StatusOK)
			_, writeErr := w.Write(crlBytes)
			Expect(writeErr).NotTo(HaveOccurred())
		})

		ts := httptest.NewUnstartedServer(mux)
		ts.Listener = listener
		ts.Start()
		defer ts.Close()

		customizer := &MutualTLSWithCRLCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err = customizer.CustomizeServerTLS(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.VerifyConnection).NotTo(BeNil())
	})

	It("returns error when CA certificate has no CRLDistributionPoints and RevocationList is empty", func() {
		customizer := &MutualTLSWithCRLCustomizer{
			Certificate: "testdata/pki/cacert.pem",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(MatchError(ErrNoUsableCRL))
	})

	It("returns error when CRL discovery fails for all distribution points", func() {
		customizer := &MutualTLSWithCRLCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(MatchError(ErrNoUsableCRL))
	})

	It("returns error when CRL is expired", func() {
		restore := SetTimeNowForTest(func() time.Time {
			return time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
		})
		defer restore()

		customizer := &MutualTLSWithCRLCustomizer{
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			RevocationList: "testdata/pki/intermediate/crl.pem",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(MatchError(ErrCRLExpired))
	})

	It("chains with existing VerifyConnection callback", func() {
		customizer := &MutualTLSWithCRLCustomizer{
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			RevocationList: "testdata/pki/intermediate/crl.pem",
		}
		called := false
		prevErr := errors.New("previous verification failed")
		cfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			VerifyConnection: func(_ tls.ConnectionState) error {
				called = true
				return prevErr
			},
		}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).NotTo(HaveOccurred())
		connErr := cfg.VerifyConnection(tls.ConnectionState{})
		Expect(connErr).To(MatchError(prevErr))
		Expect(called).To(BeTrue())
	})

	It("returns error when VerifyConnection has no peer certificates", func() {
		customizer := &MutualTLSWithCRLCustomizer{
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			RevocationList: "testdata/pki/intermediate/crl.pem",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).NotTo(HaveOccurred())
		connErr := cfg.VerifyConnection(tls.ConnectionState{})
		Expect(connErr).To(MatchError(ErrMissingPeerCertificate))
	})

	It("verifies client certificates against CRL loaded from file", func() {
		serverProv := &ServerCertificateProvider{
			Certificate: "testdata/pki/intermediate/server/fullchain.pem",
		}
		serverCfg, err := serverProv.ProvideServerTLS()
		Expect(err).NotTo(HaveOccurred())

		customizer := &MutualTLSWithCRLCustomizer{
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			RevocationList: "testdata/pki/intermediate/crl.pem",
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

	It("verifies client certificates against CRL loaded from string content", func() {
		crlBytes, err := os.ReadFile("testdata/pki/intermediate/crl.pem")
		Expect(err).NotTo(HaveOccurred())

		serverProv := &ServerCertificateProvider{
			Certificate: "testdata/pki/intermediate/server/fullchain.pem",
		}
		serverCfg, err := serverProv.ProvideServerTLS()
		Expect(err).NotTo(HaveOccurred())

		customizer := &MutualTLSWithCRLCustomizer{
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			RevocationList: string(crlBytes),
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

		revokedClient := &ClientCertificateProvider{
			Certificate:      "testdata/pki/intermediate/revoked/fullchain.pem",
			RootCertificates: "testdata/pki/cacert.pem",
		}
		_, err = sendRequest(revokedClient, baseURL)
		Expect(err).To(HaveOccurred())
	})

	It("fetches CRL over HTTP using resty", func() {
		crlBytes, err := os.ReadFile("testdata/pki/intermediate/crl.pem")
		Expect(err).NotTo(HaveOccurred())

		crlAddr, crlCleanup := startCRLServer(crlBytes)
		defer crlCleanup()

		serverProv := &ServerCertificateProvider{
			Certificate: "testdata/pki/intermediate/server/fullchain.pem",
		}
		serverCfg, err := serverProv.ProvideServerTLS()
		Expect(err).NotTo(HaveOccurred())

		customizer := &MutualTLSWithCRLCustomizer{
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			RevocationList: "http://" + crlAddr + "/crl.pem",
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

		revokedClient := &ClientCertificateProvider{
			Certificate:      "testdata/pki/intermediate/revoked/fullchain.pem",
			RootCertificates: "testdata/pki/cacert.pem",
		}
		_, err = sendRequest(revokedClient, baseURL)
		Expect(err).To(HaveOccurred())
	})

	It("fetches CRL over HTTPS using resty and TLSProvider", func() {
		crlBytes, err := os.ReadFile("testdata/pki/intermediate/crl.pem")
		Expect(err).NotTo(HaveOccurred())

		serverProv := &ServerCertificateProvider{
			Certificate: "testdata/pki/intermediate/server/fullchain.pem",
		}
		crlServerCfg, err := serverProv.ProvideServerTLS()
		Expect(err).NotTo(HaveOccurred())

		crlAddr, crlCleanup := startHTTPSCRLServer(crlBytes, crlServerCfg)
		defer crlCleanup()

		targetServerCfg, err := serverProv.ProvideServerTLS()
		Expect(err).NotTo(HaveOccurred())

		customizer := &MutualTLSWithCRLCustomizer{
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			RevocationList: "https://" + crlAddr + "/crl.pem",
			TLSProvider: &ClientCertificateProvider{
				RootCertificates: "testdata/pki/cacert.pem",
			},
		}
		err = customizer.CustomizeServerTLS(targetServerCfg)
		Expect(err).NotTo(HaveOccurred())

		addr, cleanup := startTLSServer(targetServerCfg)
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
