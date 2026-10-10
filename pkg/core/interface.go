package core

import (
	"encoding/gob"

	. "github.com/BeamFoundry/rays/pkg/lang"
)

// GrantedAuthority represent an authority a user is given.
type GrantedAuthority interface {
	// Authority() returns the authority as a string.
	Authority() string
}

// Authority is a utility type to ease the creation of [GrantedAuthority]
//
// Example :
//
//	var authorities []GrantedAuthority = []GrantedAuthority{Authority("ROLE_USER")}
type Authority string

// Authority() implements [GrantedAuthority.Authority].
func (this Authority) Authority() string {
	return string(this)
}

// Principal represent a the notion of a principal,
// which can be used to represent any entity
type Principal interface {
	GetName() string
}

// Authentication represent an authentication request or
// and authenticated principal, once processed by an [AuthenticationManager.Authenticate].
type Authentication interface {
	Principal
	// GetAuthorities() returns the authorities this principal has been granted.
	GetAuthorities() []GrantedAuthority

	// GetCredentials() returns the credentials that prove the principal is correct.
	GetCredentials() any

	// GetPrincipal() The identity of the principal being authenticated.
	GetPrincipal() any

	// IsAuthenticated() returns whether that principal has been authenticated.
	IsAuthenticated() bool

	// SetAuthenticated() will change the current status of authentication of this principal.
	// SetAuthenticated(authenticated bool)
}

// CredentialsContainer represent an interface facilating credential suppression after an
// Authentication succeeded.
//
// NOTE: Not used for now
type CredentialsContainer interface {
	// EraseCredentials() will proceed on erasing the credentials.
	EraseCredentials()
}

// UserDetails provide core user informations.
type UserDetails interface {
	// GetUsername() returns the username used to authenticate the user.
	GetUsername() string

	// GetPassword() returns the password used to authenticate the user.
	GetPassword() string

	// GetAuthorities() returns the authorities granted to the user.
	GetAuthorities() []GrantedAuthority

	// IsExpired() indicates whether the user's account has expired.
	IsExpired() bool

	// IsCredentialExpired() indicates whether the user's credentials (password) has expired.
	IsCredentialExpired() bool

	// IsDisabled() indicates whether the user's credentials (password) has expired.
	IsDisabled() bool

	// IsLocked() indicates whether the user is enabled or disabled.
	IsLocked() bool
}

// UserDetailsService is an interface used by in internal [AuthenticationProvider]
// for retrieving a username, password and other attributes for user authenticating,
// using a username and password
type UserDetailsService interface {
	// LoadUserByUsername() should return a [UserDetails] given it's username or nil.
	LoadUserByUsername(username string) UserDetails
}

// AuthenticationProvider will handle authentication for a specific [Authentication].
type AuthenticationProvider interface {
	// Authenticate() will return an authenticated [Authenication] or an AuthenticationException
	Authenticate(Authentication) (Authentication, AuthenticationException)

	// Supports() should return whether this [AuthenticationProvider] supports this [Authentication]
	Supports(Authentication) bool
}

// Manager is a marker interface to differentiate [AuthenticationProvider] and
// [AuthenticationManager] Authenticate method
type Manager interface {
	_Manager()
}

// AuthenticationManager is an interface that will delegate [Authenticate] to
// one of [AuthenticationProvider] supporting it.
type AuthenticationManager interface {
	Manager

	// Authenticate() will return an authenticated [Authenication] or an AuthenticationException.
	// It will delegate this to a configured [AuthenticationProvider] supporting this [Authentication]
	Authenticate(Authentication) (Authentication, AuthenticationException)
}

// PasswordEncoder is the interface representing a way to encode and match a password.
type PasswordEncoder interface {
	// Encode() will encode a password or generate and error.
	Encode(password []byte) ([]byte, error)

	// Matches() will check if a submittes password match.
	Matches(password, encoded []byte) bool
}

// RememberMeService represent a remember-me service
type RememberMeService interface {
	AutoLogin(handler SecurityHandler) (Authentication, Error)
	LoginSuccess(handler SecurityHandler, successfulAuthentication Authentication)
	LoginFail(handler SecurityHandler)
	Logout(handler SecurityHandler)
}

/*
type JwtTokenManager interface {
	CreateToken(claims jwt.MapClaims) (string, error)
	DecodeToken(t string) (*jwt.Token, error)
}
*/

func init() {
	var authority Authority
	gob.Register(authority)
}
