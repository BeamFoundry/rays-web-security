package certs

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"

	. "github.com/BeamFoundry/rays/pkg/lang"
	"golang.org/x/crypto/acme/autocert"
)

// ACMECertificateProvider is a struct implementing the [ServerTLSProvider] interface.
type ACMECertificateProvider struct {
	// AutoCertManager manages TLS certificates automatically using the ACME protocol,
	// Enables integration with Let's Encrypt or other ACME-compatible providers.
	//
	// Default: nil
	AutoCertManager *autocert.Manager `json:"auto_cert_manager"`

	// TLSMinVersion allows to set TLS minimum version.
	//
	// Default: tls.VersionTLS12
	// WARNING: TLS1.0 and TLS1.1 versions are not supported.
	TLSMinVersion uint16 `json:"tls_min_version"`
}

var _ ServerTLSProvider = &ACMECertificateProvider{}

// ProvideServerTLS implements [ServerTLSProvider].
func (p *ACMECertificateProvider) ProvideServerTLS() (*tls.Config, Error) {
	var tlsConfig *tls.Config

	minVersion := p.TLSMinVersion
	if minVersion == 0 {
		minVersion = tls.VersionTLS12
	}

	if minVersion != tls.VersionTLS12 && minVersion != tls.VersionTLS13 {
		return nil, ErrUnsupportedTLSVersion
	}
	if p.AutoCertManager != nil {
		tlsConfig = &tls.Config{
			MinVersion:     minVersion,
			GetCertificate: p.AutoCertManager.GetCertificate,
			NextProtos:     []string{"http/1.1", "acme-tls/1"},
		}
	}

	return tlsConfig, nil
}

// ServerCertificateProvider is a struct implementing [ServerTLSProvider].
type ServerCertificateProvider struct {
	// Certificate is either a path to a file or the content of the file instead.
	//
	// It must contain, in order, in PEM format the certificate, key and any additional
	// intermediate CA certificate signing this certificate.
	//
	// Default: ""
	Certificate string `json:"certificate"`

	// CertFile is a path of certificate file.
	// If you want to use TLS, you should enter this field or use "Certificate".
	//
	// Default: ""
	//
	// Deprecated: Use Certificate instead.
	CertFile string `json:"cert_file"`

	// KeyFile is a path of certificate's private key.
	// If you want to use TLS, you should enter this field or use "Certificate".
	//
	// Default: ""
	//
	// Deprecated: Use Certificate instead.
	CertKeyFile string `json:"cert_key_file"`

	// TLSMinVersion allows to set TLS minimum version.
	//
	// Default: tls.VersionTLS12
	// WARNING: TLS1.0 and TLS1.1 versions are not supported.
	TLSMinVersion uint16 `json:"tls_min_version"`
}

var _ ServerTLSProvider = &ServerCertificateProvider{}

// ProvideServerTLS implements [ServerTLSProvider].
func (p *ServerCertificateProvider) ProvideServerTLS() (*tls.Config, Error) {
	var tlsConfig *tls.Config

	minVersion := p.TLSMinVersion
	if minVersion == 0 {
		minVersion = tls.VersionTLS12
	}

	if minVersion != tls.VersionTLS12 && minVersion != tls.VersionTLS13 {
		return nil, ErrUnsupportedTLSVersion
	}

	setCert := func(cert tls.Certificate) {
		tlsConfig = &tls.Config{
			MinVersion:   minVersion,
			Certificates: []tls.Certificate{cert},
		}
	}

	switch {
	case p.Certificate != "":
		if block, _ := pem.Decode([]byte(p.Certificate)); block != nil {
			cert, err := tls.X509KeyPair([]byte(p.Certificate), []byte(p.Certificate))
			if err != nil {
				return nil, NewWrappedError("tls", fmt.Errorf("cannot load TLS key pair from CertificateChain: %w", err))
			}
			setCert(cert)
		} else {
			cert, err := tls.LoadX509KeyPair(p.Certificate, p.Certificate)
			if err != nil {
				return nil, NewWrappedError("tls", fmt.Errorf("cannot load TLS key pair from CertificateChain: %w", err))
			}
			setCert(cert)
		}
	case p.CertFile != "" && p.CertKeyFile != "":
		cert, err := tls.LoadX509KeyPair(p.CertFile, p.CertKeyFile)
		if err != nil {
			return nil, NewWrappedError("tls", fmt.Errorf("cannot load TLS key pair from certFile=%q and keyFile=%q: %w", p.CertFile, p.CertKeyFile, err))
		}
		setCert(cert)
	case p.CertFile != "" || p.CertKeyFile != "":
		return nil, NewWrappedError("tls", fmt.Errorf("both CertFile and CertKeyFile must be set, got certFile=%q, certKeyFile=%q: %w", p.CertFile, p.CertKeyFile, ErrIncompleteCertKeyFile))
	default:
	}

	return tlsConfig, nil
}
