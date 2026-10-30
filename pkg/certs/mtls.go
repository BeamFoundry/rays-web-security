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

// MutualTLSCustomizer is a struct implementing [ServerTLSCustomizer].
type MutualTLSCustomizer struct {
	// Certificate is either a path to a file or the content of the file instead.
	// It must be a PEM encoded CA certificate.
	//
	// Default: ""
	Certificate string `json:"certificate"`
}

var _ ServerTLSCustomizer = &MutualTLSCustomizer{}

// CustomizeServerTLS implements [ServerTLSCustomizer].
//
// It parses the Certificate, either a file path or its content, a PEM encoded CA certificate.
// It will add the certificate to config.ClientCAs and set config.ClientAuth to tls.RequireAndVerifyClientCert.
func (c *MutualTLSCustomizer) CustomizeServerTLS(cfg *tls.Config) Error {
	certificate, err := c.ClientCertificate()
	if err != nil {
		return err
	} else if certificate == nil {
		return nil
	}
	if cfg.ClientCAs == nil {
		cfg.ClientCAs = x509.NewCertPool()
	}
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs.AddCert(certificate)
	return nil
}

// ClientCertificate provides a way to retrieve the configured Client CA certificate.
func (c *MutualTLSCustomizer) ClientCertificate() (*x509.Certificate, Error) {
	if c.Certificate == "" {
		return nil, nil //nolint:nilnil // Returning nil cert without error when certificate is empty is intentional
	}

	var block *pem.Block

	if b, _ := pem.Decode([]byte(c.Certificate)); b != nil {
		block = b
	} else {
		file, err := os.ReadFile(filepath.Clean(c.Certificate))
		if err != nil {
			return nil, NewWrappedError("tls", fmt.Errorf("failed to read file from path: %w", err))
		}
		if b, _ := pem.Decode(file); b != nil {
			block = b
		}
	}

	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrNoCertificatePEMBlock
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, NewWrappedError("tls", fmt.Errorf("cannot load client CA certificate: %w", err))
	}

	return cert, nil
}
