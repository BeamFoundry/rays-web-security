package config

import (
	"crypto/x509"
)

// PreAuth holds the configuration parameters for pre-authentication.
type PreAuth struct {
	principalHeader    string
	credentialsHeader  string
	rolesHeader        string
	rolesDelimiter     string
	trustedProxies     []string
	allowMtlsFallback  bool
	exceptionOnMissing bool
}

//nolint:gocritic // Constructor.
func (this PreAuth) newPreAuth() *PreAuth {
	this.principalHeader = "X-Remote-User"
	this.rolesDelimiter = ","
	this.allowMtlsFallback = true
	return &this
}

// PrincipalHeader returns the HTTP request header name used to extract the pre-authenticated principal.
func (this *PreAuth) PrincipalHeader() string {
	return this.principalHeader
}

// CredentialsHeader returns the HTTP request header name used to extract credentials.
func (this *PreAuth) CredentialsHeader() string {
	return this.credentialsHeader
}

// RolesHeader returns the HTTP request header name used to extract user roles/authorities.
func (this *PreAuth) RolesHeader() string {
	return this.rolesHeader
}

// RolesDelimiter returns the delimiter used to split the roles header value.
func (this *PreAuth) RolesDelimiter() string {
	return this.rolesDelimiter
}

// AllowMtlsFallback returns whether to fallback to direct mTLS client certificates if no header is found.
func (this *PreAuth) AllowMtlsFallback() bool {
	return this.allowMtlsFallback
}

// TrustedProxies returns the allow-listed proxy identifiers, if any.
func (this *PreAuth) TrustedProxies() []string {
	return this.trustedProxies
}

// IsTrustedProxy checks whether the given certificate matches the allow-listed trusted proxies.
func (this *PreAuth) IsTrustedProxy(cert *x509.Certificate) bool {
	if len(this.trustedProxies) == 0 || cert == nil {
		return false
	}
	for _, proxy := range this.trustedProxies {
		if proxy == "" {
			continue
		}
		if proxy == cert.Subject.CommonName || proxy == cert.Subject.String() {
			return true
		}
	}
	return false
}

// ExceptionOnMissing returns whether missing pre-authenticated credentials immediately triggers 403 Forbidden.
func (this *PreAuth) ExceptionOnMissing() bool {
	return this.exceptionOnMissing
}

// PreAuthConfigurer lets you configure Pre-Authentication in an [HttpSecurityBuilder].
type PreAuthConfigurer struct {
	next *HttpSecurityBuilder
}

func (this PreAuthConfigurer) newConfigurer(httpSecurityBuilder *HttpSecurityBuilder) *PreAuthConfigurer {
	this.next = httpSecurityBuilder
	this.next.httpSecurity.preAuth = PreAuth{}.newPreAuth()
	return &this
}

// PrincipalHeader sets the HTTP request header name used to extract the pre-authenticated principal.
//
// Defaults to "X-Remote-User".
func (this *PreAuthConfigurer) PrincipalHeader(header string) *PreAuthConfigurer {
	this.next.httpSecurity.preAuth.principalHeader = header
	return this
}

// CredentialsHeader sets the HTTP request header name used to extract credentials.
//
// Defaults to empty (no credentials header).
func (this *PreAuthConfigurer) CredentialsHeader(header string) *PreAuthConfigurer {
	this.next.httpSecurity.preAuth.credentialsHeader = header
	return this
}

// RolesHeader sets the HTTP request header name used to extract user roles/authorities.
//
// Defaults to empty (no roles header).
func (this *PreAuthConfigurer) RolesHeader(header string) *PreAuthConfigurer {
	this.next.httpSecurity.preAuth.rolesHeader = header
	return this
}

// RolesDelimiter sets the delimiter used to split the roles header value.
//
// Defaults to ",".
func (this *PreAuthConfigurer) RolesDelimiter(delim string) *PreAuthConfigurer {
	this.next.httpSecurity.preAuth.rolesDelimiter = delim
	return this
}

// AllowMtlsFallback configures whether to fallback to direct mTLS client certificates
// if no principal is found in request headers.
//
// Defaults to true.
func (this *PreAuthConfigurer) AllowMtlsFallback(allow bool) *PreAuthConfigurer {
	this.next.httpSecurity.preAuth.allowMtlsFallback = allow
	return this
}

// TrustedProxies configures allow-listed proxy identifiers (e.g. CommonName or Subject)
// from which pre-authenticated request headers are accepted.
func (this *PreAuthConfigurer) TrustedProxies(proxies ...string) *PreAuthConfigurer {
	for _, proxy := range proxies {
		if proxy != "" {
			this.next.httpSecurity.preAuth.trustedProxies = append(this.next.httpSecurity.preAuth.trustedProxies, proxy)
		}
	}
	return this
}

// ExceptionOnMissing configures whether to immediately reject the request with 403 Forbidden
// if the pre-authenticated principal header is missing, rather than letting downstream filters evaluate.
//
// Defaults to false.
func (this *PreAuthConfigurer) ExceptionOnMissing(exception bool) *PreAuthConfigurer {
	this.next.httpSecurity.preAuth.exceptionOnMissing = exception
	return this
}

// And returns to [HttpSecurityBuilder].
func (this *PreAuthConfigurer) And() *HttpSecurityBuilder {
	return this.next
}
