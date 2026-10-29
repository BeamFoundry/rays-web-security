package chain

import (
	"context"
	"crypto/x509"
	"strings"

	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"

	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

type PreAuthFilter struct {
	Component
	Prototype

	authenticationManager AuthenticationManager `@:"Inject"`
	securityContextHolder SecurityContextHolder `@:"Inject"`
	httpSecurity          *HttpSecurity
}

var _, _ = any(&PreAuthFilter{}).(Stereotype)

var _ SecurityFilter = &PreAuthFilter{}

func (this *PreAuthFilter) WithContext(ctx context.Context) Error {
	if ct := ctx.Value(PrototypeContextParentInstance); ct != nil {
		httpSecurity, ok := ct.(*HttpSecurity)
		if !ok {
			return NewError("IllegalArgumentException", "Only HttpSecurity may inject this type")
		}
		if httpSecurity.PreAuth() == nil {
			return NewError("IllegalArgumentException", "HttpSecurity must accept PreAuth to use this filter.")
		}
		this.httpSecurity = httpSecurity
	}
	return nil
}

// Authenticate implements [SecurityFilter].
func (this *PreAuthFilter) Authenticate(handler SecurityHandler) SecurityFilterChainException {
	if this.httpSecurity == nil || this.httpSecurity.PreAuth() == nil {
		return DefaultSecurityFilterChainException{}.Next()
	}
	preAuth := this.httpSecurity.PreAuth()

	var principal any
	var credentials any
	var authorities []GrantedAuthority

	// Check if a verified mTLS certificate is present on the connection
	var cert *x509.Certificate
	if tlsHandler, ok := handler.(TLSConnectionHandler); ok {
		state := tlsHandler.TLSConnectionState()
		if state != nil && len(state.PeerCertificates) > 0 && len(state.VerifiedChains) > 0 {
			cert = state.PeerCertificates[0]
		}
	}

	// Determine if headers can be trusted:
	// - If trusted proxies are configured, headers are accepted ONLY from a verified allow-listed proxy.
	// - If no trusted proxies are configured, header and mTLS modes are mutually exclusive:
	//   a verified mTLS identity cannot be overridden by an untrusted request header.
	allowHeaders := false
	if len(preAuth.TrustedProxies()) > 0 {
		allowHeaders = preAuth.IsTrustedProxy(cert)
	} else {
		allowHeaders = cert == nil
	}

	// 1. Primary: Extract from Headers (Choice A) when headers are allowed
	if allowHeaders {
		if headerName := preAuth.PrincipalHeader(); headerName != "" {
			if headerVal := handler.Header(headerName); headerVal != "" {
				principal = headerVal
			}
		}
		if credHeader := preAuth.CredentialsHeader(); credHeader != "" {
			if credVal := handler.Header(credHeader); credVal != "" {
				credentials = credVal
			}
		}
		if rolesHeader := preAuth.RolesHeader(); rolesHeader != "" {
			if rolesVal := handler.Header(rolesHeader); rolesVal != "" {
				delim := preAuth.RolesDelimiter()
				if delim == "" {
					delim = ","
				}
				for r := range strings.SplitSeq(rolesVal, delim) {
					trimmed := strings.TrimSpace(r)
					if trimmed != "" {
						authorities = append(authorities, Authority(trimmed))
					}
				}
			}
		}
	}

	// 2. Direct mTLS fallback (Choice B): if principal wasn't derived from headers,
	// and a verified certificate is present, mTLS fallback is enabled, and cert is not a trusted proxy.
	if (principal == nil || principal == "") && cert != nil && preAuth.AllowMtlsFallback() && !preAuth.IsTrustedProxy(cert) {
		switch {
		case cert.Subject.CommonName != "":
			principal = cert.Subject.CommonName
		case len(cert.EmailAddresses) > 0:
			principal = cert.EmailAddresses[0]
		default:
			principal = cert.Subject.String()
		}
		credentials = cert
		authorities = nil
	}

	// If no principal was found
	if principal == nil || principal == "" {
		if preAuth.ExceptionOnMissing() {
			err := NewError("HttpException", "Pre-authenticated credentials missing")
			return DefaultSecurityFilterChainException{}.ReportError(err, 403)
		}
		return DefaultSecurityFilterChainException{}.Next()
	}

	token := PreAuthenticatedAuthenticationToken{}.New(principal, credentials)
	if len(authorities) > 0 {
		token.Authorities = authorities
	}

	auth, authEx := this.authenticationManager.Authenticate(token)
	if authEx != nil {
		return DefaultSecurityFilterChainException{}.ReportError(authEx, 403)
	}

	this.securityContextHolder.GetContext().SetAuthentication(auth)
	return DefaultSecurityFilterChainException{}.Next()
}

// AuthenticationRequired implements [SecurityFilter].
func (this *PreAuthFilter) AuthenticationRequired(_ SecurityHandler) SecurityFilterChainException {
	err := NewError("HttpException", "Pre-authenticated credentials required")
	return DefaultSecurityFilterChainException{}.ReportError(err, 403)
}
