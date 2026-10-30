package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	. "github.com/BeamFoundry/rays/pkg/lang"
)

var systemCertPool = x509.SystemCertPool

// ClientCertificateProvider is a struct implementing [ClientTLSProvider].
type ClientCertificateProvider struct {
	// Certificate is either a path to a file or the content of the file instead.
	//
	// It must contain, in order, in PEM format the certificate, key and any additional
	// intermediate CA certificate signing this certificate.
	//
	// Default: ""
	Certificate string `json:"certificate"`

	// RootCertificates is either a path to a file or the content of the file instead.
	//
	// It must contain in PEM format a list of CA certificates to add to the certificate pool,
	// permitting to authenticate a remote server.
	//
	// Default: ""
	RootCertificates string `json:"root_certificates"`

	// IncludeSystemCertificates allows to inherit CA certificates from the system.
	//
	// Default: false
	IncludeSystemCertificates bool `json:"include_system_certificates"`

	// TLSMinVersion allows to set TLS minimum version.
	//
	// Default: tls.VersionTLS12
	TLSMinVersion uint16 `json:"tls_min_version"`
}

var _ ClientTLSProvider = &ClientCertificateProvider{}

// ProvideClientTLS implements [ClientTLSProvider].
func (p *ClientCertificateProvider) ProvideClientTLS() (*tls.Config, Error) {
	minVersion := p.TLSMinVersion
	if minVersion == 0 {
		minVersion = tls.VersionTLS12
	}

	if minVersion != tls.VersionTLS12 && minVersion != tls.VersionTLS13 {
		return nil, ErrUnsupportedTLSVersion
	}

	if p.Certificate == "" && p.RootCertificates == "" && !p.IncludeSystemCertificates {
		return nil, nil //nolint:nilnil // Returning nil config without error when provider is unconfigured is intentional
	}

	tlsConfig := &tls.Config{
		MinVersion: minVersion,
	}

	if p.IncludeSystemCertificates {
		root, err := systemCertPool()
		if err != nil {
			return nil, NewWrappedError("clienttls", fmt.Errorf("cannot load system root certificates: %w", err))
		}
		tlsConfig.RootCAs = root
	} else {
		tlsConfig.RootCAs = x509.NewCertPool()
	}

	if p.Certificate != "" {
		if block, _ := pem.Decode([]byte(p.Certificate)); block != nil {
			cert, err := tls.X509KeyPair([]byte(p.Certificate), []byte(p.Certificate))
			if err != nil {
				return nil, NewWrappedError("clienttls", fmt.Errorf("cannot load TLS key pair from Certificate: %w", err))
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		} else {
			cert, err := tls.LoadX509KeyPair(p.Certificate, p.Certificate)
			if err != nil {
				return nil, NewWrappedError("clienttls", fmt.Errorf("cannot load TLS key pair from Certificate: %w", err))
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	appendRootAndReturn := func(cas []byte) (*tls.Config, Error) {
		if !tlsConfig.RootCAs.AppendCertsFromPEM(cas) {
			return nil, ErrAppendRootCertificates
		}
		return tlsConfig, nil
	}

	if p.RootCertificates != "" {
		if block, _ := pem.Decode([]byte(p.RootCertificates)); block != nil {
			return appendRootAndReturn([]byte(p.RootCertificates))
		}
		file, err := os.ReadFile(filepath.Clean(p.RootCertificates))
		if err != nil {
			return nil, NewWrappedError("clienttls", fmt.Errorf("cannot load file for root certificates: %w", err))
		}
		if block, _ := pem.Decode(file); block != nil {
			return appendRootAndReturn(file)
		}
		return nil, ErrUnableToLoadRootCert
	}

	return tlsConfig, nil
}
