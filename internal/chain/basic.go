package chain

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"unsafe"

	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"

	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

type BasicAuthFilter struct {
	Component
	Prototype

	authenticationManager AuthenticationManager `@:"Inject"`
	securityContextHolder SecurityContextHolder `@:"Inject"`
}

var _, _ = any(&BasicAuthFilter{}).(Stereotype)

var _ SecurityFilter = &BasicAuthFilter{}

func (this *BasicAuthFilter) WithContext(ctx context.Context) Error {
	if ct := ctx.Value(PrototypeContextParentInstance); ct != nil {
		httpSecurity, ok := (ct).(*HttpSecurity)
		if !ok {
			return NewError("IllegalArgumentException", "Only HttpSecurity may inject this type")
		}
		if !httpSecurity.Basic() {
			return NewError("IllegalArgumentException", "HttpSecurity must accept BasicAuth to use this filter.")
		}
	}
	return nil
}

// Authenticate implements [SecurityFilter].
func (this *BasicAuthFilter) Authenticate(handler SecurityHandler) SecurityFilterChainException {
	header := handler.Header("Authorization")
	if header == "" {
		return DefaultSecurityFilterChainException{}.Next()
	} else if len(header) <= 6 || !String(header[:6]).ToLowerCase().Equals("basic ") {
		err := NewError("IllegalArgumentException", "'Authorization' header must start with 'Basic'")
		return DefaultSecurityFilterChainException{}.ReportError(err, http.StatusBadRequest)
	}
	raw, err := base64.StdEncoding.DecodeString(header[6:])
	if err != nil {
		return DefaultSecurityFilterChainException{}.ReportError(NewError("IllegalArgumentException", err.Error()), http.StatusBadRequest)
	}
	creds := this.unsafeString(raw)
	before, after, ok := strings.Cut(creds, ":")
	if !ok {
		err := NewError("IllegalArgumentException", "'Authorization' must contain Base64 encoded, separated by colon, username and password")
		return DefaultSecurityFilterChainException{}.ReportError(err, http.StatusBadRequest)
	}
	username := before
	password := after
	token := UsernamePasswordAuthenticationToken{}.New(username, password)
	authentication, err := this.authenticationManager.Authenticate(token)
	if err != nil {
		return DefaultSecurityFilterChainException{}.ReportError(NewError("HttpException", "Authentication Required"), 401)
	}
	this.securityContextHolder.GetContext().SetAuthentication(authentication)
	return DefaultSecurityFilterChainException{}.Next()
}

// AuthenticationRequired implements [SecurityFilter].
func (this *BasicAuthFilter) AuthenticationRequired(handler SecurityHandler) SecurityFilterChainException {
	handler.SetHeader("WWW-Authenticate", "basic realm="+"Restricted")
	return DefaultSecurityFilterChainException{}.ReportError(NewError("HttpException", "Authentication Required"), 401)
}

// UnsafeString returns a string pointer without allocation
func (this *BasicAuthFilter) unsafeString(b []byte) string {
	// the new way is slower `return unsafe.String(unsafe.SliceData(b), len(b))`
	// unsafe.Pointer variant: 0.3538 ns/op vs unsafe.String variant: 0.5410 ns/op
	// #nosec G103
	return *(*string)(unsafe.Pointer(&b))
}
