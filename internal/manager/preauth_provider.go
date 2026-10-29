package manager

import (
	"reflect"

	. "github.com/BeamFoundry/rays/pkg/lang"

	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

// PreAuthenticatedAuthenticationProvider processes [PreAuthenticatedAuthenticationToken] instances.
//
// It delegates user retrieval to an [AuthenticationUserDetailsService] and validates account status.
type PreAuthenticatedAuthenticationProvider struct {
	service AuthenticationUserDetailsService
}

var _ AuthenticationProvider = &PreAuthenticatedAuthenticationProvider{}

// New() creates a new [PreAuthenticatedAuthenticationProvider].
func (this PreAuthenticatedAuthenticationProvider) New(service AuthenticationUserDetailsService) *PreAuthenticatedAuthenticationProvider {
	this.service = service
	return &this
}

// Supports() implements [AuthenticationProvider.Supports].
func (this *PreAuthenticatedAuthenticationProvider) Supports(authentication Authentication) bool {
	return reflect.TypeOf(authentication) == reflect.TypeFor[*PreAuthenticatedAuthenticationToken]()
}

// Authenticate() implements [AuthenticationProvider.Authenticate].
func (this *PreAuthenticatedAuthenticationProvider) Authenticate(authentication Authentication) (Authentication, AuthenticationException) {
	token, ok := authentication.(*PreAuthenticatedAuthenticationToken)
	if !ok || token.GetPrincipal() == nil || token.GetPrincipal() == "" {
		return nil, BadCredentialsException{}.New("PreAuthenticatedAuthenticationProvider: No pre-authenticated principal found", authentication)
	}

	if !reflect.ValueOf(this.service).IsValid() {
		return nil, InternalAuthenticationException{}.New("AuthenticationUserDetailsService is not available", authentication)
	}

	user, loadErr := this.service.LoadUserDetails(token)
	if loadErr != nil {
		return nil, loadErr
	}
	if user == nil {
		return nil, BadCredentialsException{}.New("PreAuthenticatedAuthenticationProvider: UserDetails is nil", authentication)
	}

	err := Try(
		func() {
			_ = user.IsExpired() && RaiseErr(AccountExpiredException{}.New("UserDetailsService: User is expired", authentication))
			_ = user.IsCredentialExpired() && RaiseErr(CredentialsExpiredException{}.New("UserDetailsService: User credentials have expired", authentication))
			_ = user.IsLocked() && RaiseErr(LockedException{}.New("UserDetailsService: User is locked", authentication))
			_ = user.IsDisabled() && RaiseErr(DisabledException{}.New("UserDetailsService: User is disabled", authentication))
		},
		Catch(func(e AuthenticationException) Error {
			return e
		}),
	)
	if exception, ok := err.(AuthenticationException); ok {
		return nil, exception
	}

	authorities := user.GetAuthorities()
	if len(authorities) == 0 && len(token.GetAuthorities()) > 0 {
		authorities = token.GetAuthorities()
	}

	authenticated := PreAuthenticatedAuthenticationToken{}.NewAuthenticated(user, nil, authorities)
	token.EraseCredentials()
	return authenticated, nil
}
