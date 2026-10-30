package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/go-resty/resty/v2"
)

// MutualTLSWithCRLCustomizer is a struct implementing [ServerTLSCustomizer].
//
// It provides MutualTLS configuration with Certificate Revocation List check to a [tls.Config] object.
//
// CRL can be provided via a URL, a file path or directly. If none is provided, the CRL can be fetched
// from the URL defined in the CRL Distribution Endpoints.
// See: https://docs.openssl.org/3.5/man5/x509v3_config/#crl-distribution-points
//
// NOTE: Only CRL version 2 in PEM format is supported.
// See: https://docs.openssl.org/3.5/man1/openssl-ca/#crl-options
type MutualTLSWithCRLCustomizer struct {
	// TLSProvider is an optional ClientTLSProvider to configure the HTTP client that will fetch a CRL.
	//
	// Default: nil
	TLSProvider ClientTLSProvider `json:"tls_provider"`

	// Client is an optional resty.Client to use for fetching the CRL.
	// If nil, a new resty client will be created.
	Client *resty.Client `json:"-"`

	// Certificate is either a path to a file or the content of the file instead.
	// It must be a PEM encoded CA certificate.
	//
	// Default: ""
	Certificate string `json:"certificate"`

	// RevocationList is either a URL to, a path to or a CRL directly.
	//
	// Default: ""
	RevocationList string `json:"revocation_list"`

	// Timeout specifies the HTTP request timeout when fetching a CRL.
	// Default: 10 * time.Second
	Timeout time.Duration `json:"timeout"`
}

var _ ServerTLSCustomizer = &MutualTLSWithCRLCustomizer{}

// CustomizeServerTLS implements [ServerTLSCustomizer].
func (m *MutualTLSWithCRLCustomizer) CustomizeServerTLS(config *tls.Config) error {
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

	var crlBytes []byte

	if m.RevocationList != "" {
		if bytes, ok := m.decodePemCrl([]byte(m.RevocationList)); ok {
			crlBytes = bytes
		} else if distURL, urlErr := m.validateFetchURL(m.RevocationList); urlErr == nil {
			file, fetchErr := m.fetchCRL(distURL)
			if fetchErr != nil {
				return fetchErr
			}
			crlBytes = file
		} else {
			file, readErr := os.ReadFile(filepath.Clean(m.RevocationList))
			if readErr != nil {
				return fmt.Errorf("tls: failed to read CRL file from path=%q: %w", m.RevocationList, readErr)
			}
			bytes, ok := m.decodePemCrl(file)
			if !ok {
				return fmt.Errorf("tls: failed to parse CRL from path=%q", m.RevocationList)
			}
			crlBytes = bytes
		}
	} else {
		if len(clientCACert.CRLDistributionPoints) == 0 {
			return ErrNoUsableCRL
		}
		for _, dist := range clientCACert.CRLDistributionPoints {
			if distURL, urlErr := m.validateFetchURL(dist); urlErr == nil {
				if crl, fetchErr := m.fetchCRL(distURL); fetchErr == nil {
					crlBytes = crl
					break
				}
			}
		}
		if len(crlBytes) == 0 {
			return ErrNoUsableCRL
		}
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return fmt.Errorf("tls: unable to load CRL: %w", err)
	}
	if err := crl.CheckSignatureFrom(clientCACert); err != nil {
		return fmt.Errorf("tls: invalid CRL signature: %w", err)
	}
	if !crl.NextUpdate.IsZero() && timeNow().After(crl.NextUpdate) {
		return ErrCRLExpired
	}

	prevVerify := config.VerifyConnection
	config.VerifyConnection = func(cs tls.ConnectionState) error {
		if prevVerify != nil {
			if err := prevVerify(cs); err != nil {
				return err
			}
		}
		if len(cs.PeerCertificates) == 0 {
			return ErrMissingPeerCertificate
		}
		cert := cs.PeerCertificates[0]
		for _, revokedCertificate := range crl.RevokedCertificateEntries {
			if revokedCertificate.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return ErrCertificateRevoked
			}
		}
		return nil
	}

	return nil
}

func (*MutualTLSWithCRLCustomizer) decodePemCrl(crl []byte) ([]byte, bool) {
	if block, _ := pem.Decode(crl); block != nil && block.Type == "X509 CRL" {
		return block.Bytes, true
	}
	return nil, false
}

func (*MutualTLSWithCRLCustomizer) validateFetchURL(dist string) (*url.URL, error) {
	distURL, err := url.Parse(dist)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	if !slices.Contains([]string{schemeHTTP, schemeHTTPS}, distURL.Scheme) {
		return nil, fmt.Errorf("tls: CRL fetching client: wrong scheme=%q, only 'http' or 'https' is supported", distURL.Scheme)
	}
	return distURL, nil
}

func (m *MutualTLSWithCRLCustomizer) fetchCRL(distURL *url.URL) ([]byte, error) {
	client := m.Client
	if client == nil {
		client = resty.New()
	}
	if m.Timeout > 0 {
		client.SetTimeout(m.Timeout)
	}

	if distURL.Scheme == schemeHTTPS && m.TLSProvider != nil {
		tlsConfig, err := m.TLSProvider.ProvideClientTLS()
		if err != nil {
			return nil, err
		}
		client.SetTLSClientConfig(tlsConfig)
	}

	resp, err := client.R().Get(distURL.String())
	if err != nil {
		return nil, fmt.Errorf("tls: unable to fetch certificate revocation list from url=%q: %w", distURL.String(), err)
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		return nil, fmt.Errorf("tls: failed to fetch CRL from url=%q: HTTP status %d", distURL.String(), resp.StatusCode())
	}

	if bytes, ok := m.decodePemCrl(resp.Body()); ok {
		return bytes, nil
	}
	return nil, fmt.Errorf("tls: unable to parse PEM CRL from url=%q", distURL.String())
}
