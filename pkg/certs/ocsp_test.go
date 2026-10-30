package certs_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/BeamFoundry/rays/pkg/lang"
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
				err: NewError("tls", "tls provider failed"),
			},
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).To(HaveOccurred())
	})

	It("falls back to OCSPServer in CA certificate when OCSPServer is empty", func() {
		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.VerifyConnection).NotTo(BeNil())
	})

	It("chains with existing VerifyConnection callback", func() {
		called := false
		prevErr := errors.New("previous verification failed")
		serverProv := &ServerCertificateProvider{
			Certificate: "testdata/pki/intermediate/server/fullchain.pem",
		}
		serverCfg, err := serverProv.ProvideServerTLS()
		Expect(err).NotTo(HaveOccurred())
		serverCfg.VerifyConnection = func(_ tls.ConnectionState) error {
			called = true
			return prevErr
		}

		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
			OCSPServer:  "http://127.0.0.1:9999",
		}
		err = customizer.CustomizeServerTLS(serverCfg)
		Expect(err).NotTo(HaveOccurred())
		connErr := serverCfg.VerifyConnection(tls.ConnectionState{})
		Expect(connErr).To(MatchError(prevErr))
		Expect(called).To(BeTrue())
	})

	It("returns error when VerifyConnection has no peer certificates", func() {
		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate: "testdata/pki/intermediate/cacert.pem",
			OCSPServer:  "http://127.0.0.1:9999",
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		err := customizer.CustomizeServerTLS(cfg)
		Expect(err).NotTo(HaveOccurred())
		connErr := cfg.VerifyConnection(tls.ConnectionState{})
		Expect(connErr).To(MatchError(ErrMissingPeerCertificate))
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

		connErr := serverCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}})
		Expect(connErr).To(HaveOccurred())
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

		connErr := serverCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}})
		Expect(connErr).To(MatchError(ErrCertificateUnknownOCSP))
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

		connErr := serverCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}})
		Expect(connErr).To(HaveOccurred())
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

	It("fails when delegated responder certificate lacks OCSPSigning", func() {
		responder, err := NewOCSPResponder()
		Expect(err).NotTo(HaveOccurred())
		serverCert, err := parseCertFile("testdata/pki/intermediate/server/cert.pem")
		Expect(err).NotTo(HaveOccurred())
		responder.config.RespKeyFile = "testdata/pki/intermediate/server/key.pem"
		responder.respCert = serverCert

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

		connErr := serverCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}})
		Expect(connErr).To(MatchError(ErrDelegatedOCSPMissingSigning))
	})

	It("fails when OCSP response ThisUpdate exceeds max age", func() {
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
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			OCSPServer:     "http://" + ocspAddr,
			MaxResponseAge: 1 * time.Second,
		}
		err = customizer.CustomizeServerTLS(serverCfg)
		Expect(err).NotTo(HaveOccurred())

		clientCert, err := parseCertFile("testdata/pki/intermediate/client/cert.pem")
		Expect(err).NotTo(HaveOccurred())

		connErr := serverCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}})
		Expect(connErr).To(MatchError(ErrOCSPResponseTooOld))
	})

	It("fails when OCSP response has expired past NextUpdate", func() {
		restore := SetTimeNowForTest(func() time.Time {
			return time.Now().Add(48 * time.Hour)
		})
		defer restore()

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
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			OCSPServer:     "http://" + ocspAddr,
			MaxResponseAge: 72 * time.Hour,
		}
		err = customizer.CustomizeServerTLS(serverCfg)
		Expect(err).NotTo(HaveOccurred())

		clientCert, err := parseCertFile("testdata/pki/intermediate/client/cert.pem")
		Expect(err).NotTo(HaveOccurred())

		connErr := serverCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}})
		Expect(connErr).To(MatchError(ErrOCSPResponseExpired))
	})

	It("caches OCSP responses by certificate serial number until NextUpdate expires", func() {
		responder, err := NewOCSPResponder()
		Expect(err).NotTo(HaveOccurred())

		ocspAddr, ocspCleanup := startOCSPResponder(responder)

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

		// First call fetches from responder and caches
		connErr := serverCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}})
		Expect(connErr).NotTo(HaveOccurred())

		// Close responder so any new network fetch would fail
		ocspCleanup()

		// Second call succeeds because entry is cached
		connErr = serverCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}})
		Expect(connErr).NotTo(HaveOccurred())
	})

	It("applies explicit policy when NextUpdate is absent and validates response", func() {
		responder, err := NewOCSPResponder()
		Expect(err).NotTo(HaveOccurred())
		zeroTime := time.Time{}
		responder.NextUpdateOverride = &zeroTime

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

		connErr := serverCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}})
		Expect(connErr).NotTo(HaveOccurred())
	})

	It("fails when delegated OCSP responder certificate is not yet valid", func() {
		restore := SetTimeNowForTest(func() time.Time {
			return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		})
		defer restore()

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

		connErr := serverCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}})
		Expect(connErr).To(MatchError(ErrDelegatedOCSPInvalidValidity))
	})

	It("fails when delegated OCSP responder certificate is expired", func() {
		restore := SetTimeNowForTest(func() time.Time {
			return time.Date(2037, 1, 1, 0, 0, 0, 0, time.UTC)
		})
		defer restore()

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

		connErr := serverCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}})
		Expect(connErr).To(MatchError(ErrDelegatedOCSPInvalidValidity))
	})

	It("fails when OCSP response ThisUpdate is in the future", func() {
		responder, err := NewOCSPResponder()
		Expect(err).NotTo(HaveOccurred())
		futureTime := time.Now().Add(10 * time.Minute)
		responder.ThisUpdateOverride = &futureTime

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

		connErr := serverCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}})
		Expect(connErr).To(MatchError(ErrOCSPThisUpdateInFuture))
	})

	It("caps OCSP cache lifetime at ThisUpdate plus maxAge when NextUpdate is later", func() {
		responder, err := NewOCSPResponder()
		Expect(err).NotTo(HaveOccurred())
		farFuture := time.Now().Add(7 * 24 * time.Hour)
		responder.NextUpdateOverride = &farFuture

		ocspAddr, ocspCleanup := startOCSPResponder(responder)

		serverProv := &ServerCertificateProvider{
			Certificate: "testdata/pki/intermediate/server/fullchain.pem",
		}
		serverCfg, err := serverProv.ProvideServerTLS()
		Expect(err).NotTo(HaveOccurred())

		customizer := &MutualTLSWithOCSPCustomizer{
			Certificate:    "testdata/pki/intermediate/cacert.pem",
			OCSPServer:     "http://" + ocspAddr,
			MaxResponseAge: 24 * time.Hour,
		}
		err = customizer.CustomizeServerTLS(serverCfg)
		Expect(err).NotTo(HaveOccurred())

		clientCert, err := parseCertFile("testdata/pki/intermediate/client/cert.pem")
		Expect(err).NotTo(HaveOccurred())

		// First verification succeeds and caches with expiresAt capped at ThisUpdate + 24h
		connErr := serverCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}})
		Expect(connErr).NotTo(HaveOccurred())

		// Close responder so any cache miss or expired cache re-fetch fails
		ocspCleanup()

		// Advance time past the 24h cap (but still well before the 7d NextUpdate)
		simulatedTime := time.Now().Add(25 * time.Hour)
		restore := SetTimeNowForTest(func() time.Time {
			return simulatedTime
		})
		defer restore()

		// Second verification must bypass the expired cache entry and attempt network fetch, failing because responder is closed
		connErr = serverCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}})
		Expect(connErr).To(HaveOccurred())
		Expect(connErr.Error()).To(ContainSubstring("mtls:"))
	})
})
