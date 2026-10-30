package certs

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"golang.org/x/crypto/ocsp"
)

var ocspCreateRequest = ocsp.CreateRequest

type ocspCacheEntry struct {
	response  *ocsp.Response
	expiresAt time.Time
}

// MutualTLSWithOCSPCustomizer is a struct implementing [ServerTLSCustomizer].
type MutualTLSWithOCSPCustomizer struct {
	TLSProvider    ClientTLSProvider `json:"tls_provider"`
	cache          map[string]*ocspCacheEntry
	Client         *resty.Client `json:"-"`
	Certificate    string        `json:"certificate"`
	OCSPServer     string        `json:"ocsp_server"`
	Timeout        time.Duration `json:"timeout"`
	MaxResponseAge time.Duration `json:"max_response_age"`
	cacheMu        sync.RWMutex
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

		m.cacheMu.Lock()
		if m.cache == nil {
			m.cache = make(map[string]*ocspCacheEntry)
		}
		m.cacheMu.Unlock()

		maxAge := m.MaxResponseAge
		if maxAge == 0 {
			maxAge = 24 * time.Hour
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

			serialKey := cert.SerialNumber.String()
			now := timeNow()

			m.cacheMu.RLock()
			cached, hit := m.cache[serialKey]
			m.cacheMu.RUnlock()

			var ocspResponse *ocsp.Response
			if hit && now.Before(cached.expiresAt) {
				ocspResponse = cached.response
			} else {
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

				parsed, err := ocsp.ParseResponseForCert(resp.Body(), cert, clientCACert)
				if err != nil {
					return fmt.Errorf("mtls: %w", err)
				}

				if parsed.Certificate != nil && !bytes.Equal(parsed.Certificate.Raw, clientCACert.Raw) {
					if !slices.Contains(parsed.Certificate.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
						return ErrDelegatedOCSPMissingSigning
					}
				}

				if now.Sub(parsed.ThisUpdate) > maxAge {
					return ErrOCSPResponseTooOld
				}

				expiresAt := parsed.NextUpdate
				if expiresAt.IsZero() {
					expiresAt = parsed.ThisUpdate.Add(maxAge)
				}
				if now.After(expiresAt) {
					return ErrOCSPResponseExpired
				}

				ocspResponse = parsed

				m.cacheMu.Lock()
				m.cache[serialKey] = &ocspCacheEntry{
					response:  ocspResponse,
					expiresAt: expiresAt,
				}
				m.cacheMu.Unlock()
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
