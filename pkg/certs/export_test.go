package certs

import (
	"crypto/x509"

	"golang.org/x/crypto/ocsp"
)

// SetSystemCertPoolForTest sets systemCertPool for testing.
func SetSystemCertPoolForTest(fn func() (*x509.CertPool, error)) func() {
	orig := systemCertPool
	systemCertPool = fn
	return func() {
		systemCertPool = orig
	}
}

// SetOCSPCreateRequestForTest sets ocspCreateRequest for testing.
func SetOCSPCreateRequestForTest(fn func(cert, issuer *x509.Certificate, opts *ocsp.RequestOptions) ([]byte, error)) func() {
	orig := ocspCreateRequest
	ocspCreateRequest = fn
	return func() {
		ocspCreateRequest = orig
	}
}
