package certs

import (
	"crypto/tls"
	"errors"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

var (
	// ErrUnsupportedTLSVersion is returned when a TLS version other than TLS 1.2 or TLS 1.3 is specified.
	ErrUnsupportedTLSVersion = errors.New("tls: unsupported TLS version, please use tls.VersionTLS12 or tls.VersionTLS13")

	// ErrAppendRootCertificates is returned when root certificates cannot be appended to the certificate pool.
	ErrAppendRootCertificates = errors.New("clienttls: failed to append root certificates")

	// ErrUnableToLoadRootCert is returned when a root certificate cannot be parsed or loaded.
	ErrUnableToLoadRootCert = errors.New("clienttls: unable to load root certificate")

	// ErrCertificateRevoked is returned during peer verification when a certificate is identified as revoked.
	ErrCertificateRevoked = errors.New("tls: the certificate was revoked")

	// ErrCertificateUnknownOCSP is returned when the OCSP responder does not recognize the certificate.
	ErrCertificateUnknownOCSP = errors.New("tls: the certificate is unknown to OCSP server")

	// ErrTLSProviderRequiredHTTPS is returned when querying an HTTPS OCSP server without a configured TLSProvider.
	ErrTLSProviderRequiredHTTPS = errors.New("mtls: TLSProvider is required for https OCSP server")
)

// ServerTLSProvider provides an interface for creating a [*tls.Config] to be used by a server.
type ServerTLSProvider interface {
	// ProvideServerTLS provides possibly a *tls.Config object to be used by a server or
	// an error if it fails to do so.
	//
	// NOTE: Implementations may return (nil, nil) if no tls.Config can be provided and no error occurred.
	// For example when no path to a certificate is provided (empty string), instead of a wrong
	// path which will generate an error.
	ProvideServerTLS() (*tls.Config, error)
}

// ServerTLSCustomizer provides an interface for customizing an existing [*tls.Config] object configured for a server.
type ServerTLSCustomizer interface {
	CustomizeServerTLS(config *tls.Config) error
}

// ClientTLSProvider provides an interface for creating a [*tls.Config] to be used by a client.
type ClientTLSProvider interface {
	// ProvideClientTLS provides possibly a *tls.Config object to be used by a client or
	// an error if it fails to do so.
	//
	// NOTE: Implementations may return (nil, nil) if no tls.Config can be provided and no error occurred.
	// For example when no path to a certificate is provided (empty string), instead of a wrong
	// path which will generate an error.
	ProvideClientTLS() (*tls.Config, error)
}

// ConfigureServerTLS creates a [*tls.Config] from a [ServerTLSProvider] and applies any [ServerTLSCustomizer].
func ConfigureServerTLS(provider ServerTLSProvider, customizers ...ServerTLSCustomizer) (*tls.Config, error) {
	if provider == nil {
		return nil, nil //nolint:nilnil // Returning nil config without error when provider is nil is intentional
	}
	cfg, err := provider.ProvideServerTLS()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil //nolint:nilnil // Returning nil config without error when provider returns no config is intentional
	}
	for _, c := range customizers {
		if c != nil {
			if err := c.CustomizeServerTLS(cfg); err != nil {
				return nil, err
			}
		}
	}
	return cfg, nil
}

// ConfigureClientTLS creates a [*tls.Config] from a [ClientTLSProvider].
func ConfigureClientTLS(provider ClientTLSProvider) (*tls.Config, error) {
	if provider == nil {
		return nil, nil //nolint:nilnil // Returning nil config without error when provider is nil is intentional
	}
	return provider.ProvideClientTLS()
}
