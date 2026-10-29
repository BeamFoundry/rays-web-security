package auth

import (
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

// UserDetailsByNameServiceWrapper wraps a [UserDetailsService] to implement [AuthenticationUserDetailsService].
type UserDetailsByNameServiceWrapper struct {
	userDetailsService UserDetailsService
}

var _ AuthenticationUserDetailsService = &UserDetailsByNameServiceWrapper{}

// New() creates a new [UserDetailsByNameServiceWrapper].
func (this UserDetailsByNameServiceWrapper) New(service UserDetailsService) *UserDetailsByNameServiceWrapper {
	this.userDetailsService = service
	return &this
}

// LoadUserDetails() implements [AuthenticationUserDetailsService.LoadUserDetails].
func (this *UserDetailsByNameServiceWrapper) LoadUserDetails(token Authentication) (UserDetails, AuthenticationException) {
	username := token.GetName()
	switch p := token.GetPrincipal().(type) {
	case UserDetails:
		return p, nil
	case string:
		username = p
	default:
	}

	user := this.userDetailsService.LoadUserByUsername(username)
	if user == nil {
		return nil, BadCredentialsException{}.New("User not found: "+username, token)
	}
	return user, nil
}

type preAuthUserDetails struct {
	username    string
	authorities []GrantedAuthority
}

func (u *preAuthUserDetails) GetUsername() string                { return u.username }
func (u *preAuthUserDetails) GetPassword() string                { return "" }
func (u *preAuthUserDetails) GetAuthorities() []GrantedAuthority { return u.authorities }
func (u *preAuthUserDetails) IsExpired() bool                    { return false }
func (u *preAuthUserDetails) IsCredentialExpired() bool          { return false }
func (u *preAuthUserDetails) IsDisabled() bool                   { return false }
func (u *preAuthUserDetails) IsLocked() bool                     { return false }

var _ UserDetails = &preAuthUserDetails{}

// PreAuthenticatedGrantedAuthoritiesUserDetailsService creates [UserDetails] based solely
// on the authorities and principal already attached to the [Authentication] token (e.g. from upstream proxy headers).
type PreAuthenticatedGrantedAuthoritiesUserDetailsService struct{}

var _ AuthenticationUserDetailsService = &PreAuthenticatedGrantedAuthoritiesUserDetailsService{}

// New() creates a new [PreAuthenticatedGrantedAuthoritiesUserDetailsService].
func (this PreAuthenticatedGrantedAuthoritiesUserDetailsService) New() *PreAuthenticatedGrantedAuthoritiesUserDetailsService {
	return &this
}

// LoadUserDetails() implements [AuthenticationUserDetailsService.LoadUserDetails].
func (this *PreAuthenticatedGrantedAuthoritiesUserDetailsService) LoadUserDetails(token Authentication) (UserDetails, AuthenticationException) {
	username := token.GetName()
	switch p := token.GetPrincipal().(type) {
	case string:
		username = p
	case UserDetails:
		return p, nil
	default:
	}
	return &preAuthUserDetails{
		username:    username,
		authorities: token.GetAuthorities(),
	}, nil
}
