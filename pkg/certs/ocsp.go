package certs

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/go-resty/resty/v2"
	"golang.org/x/crypto/ocsp"
)

var ocspCreateRequest = ocsp.CreateRequest

// MutualTLSWithOCSPCustomizer is a struct implementing [ServerTLSCustomizer].
type MutualTLSWithOCSPCustomizer struct {
	// TLSProvider adds an optional ClientTLSProvider to configure the OCSP fetch client.
	//
	// Default: nil
	TLSProvider ClientTLSProvider `json:"tls_provider"`

	// Client is an optional resty.Client to use for querying the OCSP server.
	// If nil, a new resty client will be created.
	Client *resty.Client `json:"-"`

	// Certificate is either a path to a file or the content of the file instead.
	// It must be a PEM encoded CA certificate.
	//
	// Default: ""
	Certificate string `json:"certificate"`

	// OCSPServer is the URL of the OCSP responder.
	// If empty, the OCSP server URL defined in the client CA certificate is used.
	OCSPServer string `json:"ocsp_server"`

	// Timeout specifies the HTTP request timeout when querying the OCSP server.
	// Default: 10 * time.Second
	Timeout time.Duration `json:"timeout"`
}

var _ ServerTLSCustomizer = &MutualTLSWithOCSPCustomizer{}

// CustomizeServerTLS implements [ServerTLSCustomizer].
func (m *MutualTLSWithOCSPCustomizer) CustomizeServerTLS(config *tls.Config) error {
	mtls := &MutualTLSCustomizer{
		Certificate: m.Certificate,
	}

	clientCACert, err := mtls.ClientCertificate()
	if err != nil {
		return err
	} else if clientCACert == nil {
		return nil
	}
	if config.ClientCAs == nil {
		config.ClientCAs = x509.NewCertPool()
	}
	config.ClientAuth = tls.RequireAndVerifyClientCert
	config.ClientCAs.AddCert(clientCACert)
	if m.Timeout == 0 {
		m.Timeout = 10 * time.Second
	}

	var ocspServer string

	if m.OCSPServer != "" {
		if err := m.validateOCSPServer(m.OCSPServer); err != nil {
			return err
		}
		ocspServer = m.OCSPServer
	} else {
		for _, server := range clientCACert.OCSPServer {
			if err := m.validateOCSPServer(server); err == nil {
				ocspServer = server
				break
			}
		}
	}

	if ocspServer != "" {
		client := m.Client
		if client == nil {
			client = resty.New()
		}
		if m.Timeout > 0 {
			client.SetTimeout(m.Timeout)
		}

		//nolint:errcheck // input already verified
		ocspURL, _ := url.Parse(ocspServer)
		if ocspURL.Scheme == schemeHTTPS {
			if m.TLSProvider == nil {
				return ErrTLSProviderRequiredHTTPS
			}
			tlsConfig, err := m.TLSProvider.ProvideClientTLS()
			if err != nil {
				return err
			}
			client.SetTLSClientConfig(tlsConfig)
		}

		prevVerify := config.VerifyPeerCertificate
		config.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error { //nolint:gosec // G123: Peer certificate verification for OCSP check
			if prevVerify != nil {
				if err := prevVerify(rawCerts, verifiedChains); err != nil {
					return err
				}
			}
			cert := verifiedChains[0][0]
			opts := &ocsp.RequestOptions{Hash: crypto.SHA256}
			buffer, err := ocspCreateRequest(cert, clientCACert, opts)
			if err != nil {
				return fmt.Errorf("mtls: %w", err)
			}

			resp, err := client.R().
				SetHeader("Content-Type", "application/ocsp-request").
				SetHeader("Accept", "application/ocsp-response").
				SetBody(buffer).
				Post(ocspServer)
			if err != nil {
				return fmt.Errorf("mtls: %w", err)
			}

			if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
				return fmt.Errorf("mtls: failed to query OCSP server: HTTP status %d", resp.StatusCode())
			}

			ocspResponse, err := ocsp.ParseResponseForCert(resp.Body(), cert, clientCACert)
			if err != nil {
				return fmt.Errorf("mtls: %w", err)
			}

			switch ocspResponse.Status {
			case ocsp.Revoked:
				return ErrCertificateRevoked
			case ocsp.Unknown:
				return ErrCertificateUnknownOCSP
			default:
				return nil
			}
		}
	}

	return nil
}

func (*MutualTLSWithOCSPCustomizer) validateOCSPServer(ocspServer string) error {
	ocspURL, err := url.Parse(ocspServer)
	if err != nil {
		return fmt.Errorf("mtls: %w", err)
	}
	if !slices.Contains([]string{schemeHTTP, schemeHTTPS}, ocspURL.Scheme) {
		return fmt.Errorf("tls: OCSP Stapling: wrong scheme=%q, only 'http' or 'https' is supported", ocspURL.Scheme)
	}
	return nil
}
