package auth

import (
	"encoding/gob"
	"fmt"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

type AbstractAuthenticationToken struct {
	Principal     any                `json:"principal"`
	Authorities   []GrantedAuthority `json:"authorities"`
	Authenticated bool               `json:"authenticated"`
}

// GetPrincipal() implements [Authentication.GetCredentials].
func (this *AbstractAuthenticationToken) GetPrincipal() any {
	return this.Principal
}

func (this *AbstractAuthenticationToken) setPrincipal(principal any) {
	this.Principal = principal
}

// IsAuthenticated() implements [Authentication.IsAuthenticated]
func (this *AbstractAuthenticationToken) IsAuthenticated() bool {
	return this.Authenticated
}

func (this *AbstractAuthenticationToken) setAuthenticated(authenticated bool) {
	this.Authenticated = authenticated
}

// GetAuthorities() implements [Authentication.GetAuthorities]
func (this *AbstractAuthenticationToken) GetAuthorities() []GrantedAuthority {
	return this.Authorities
}

// GetName() implements [Principal.GetName]
func (this *AbstractAuthenticationToken) GetName() string {
	if userDetails, ok := this.GetPrincipal().(UserDetails); ok {
		return "(UserDetails)" + userDetails.GetUsername()
		/*
			} else if username, ok := this.GetPrincipal().(string); ok {
				return "(string)" + username
		*/
	}
	return fmt.Sprintf("(%T) %v", this.GetPrincipal(), this.GetPrincipal())
}

// UsernamePasswordAuthenticationToken is an implementation of Authentication representing an
// authentication by username and password.
type UsernamePasswordAuthenticationToken struct {
	credentials any
	AbstractAuthenticationToken
}

var _ Authentication = &UsernamePasswordAuthenticationToken{}

// New() is the constructor for an unauthenticated [UsernamePasswordAuthenticationToken].
func (this UsernamePasswordAuthenticationToken) New(principal, credentials any) *UsernamePasswordAuthenticationToken {
	this.setPrincipal(principal)
	this.credentials = credentials
	return &this
}

// NewAuthenticated() is the constructor for an authenticated [UsernamePasswordAuthenticationToken].
func (this UsernamePasswordAuthenticationToken) NewAuthenticated(principal, credentials any, authorities []GrantedAuthority) *UsernamePasswordAuthenticationToken {
	this.setPrincipal(principal)
	this.credentials = credentials
	this.Authorities = authorities
	this.setAuthenticated(true)
	return &this
}

// GetCredentials() implements [Authentication.GetCredentials].
func (this *UsernamePasswordAuthenticationToken) GetCredentials() any {
	return this.credentials
}

// EraseCredentials() implements [CredentialsContainer.EraseCredentials]
func (this *UsernamePasswordAuthenticationToken) EraseCredentials() {
	this.credentials = nil
}

// AnonymousAuthenticationToken is an implementation of [Authentication] representing an unauthenticated user.
type AnonymousAuthenticationToken struct {
	AbstractAuthenticationToken
}

var _ Authentication = &AnonymousAuthenticationToken{}

// New() is the constructor for [AnonymousAuthenticationToken].
func (this AnonymousAuthenticationToken) New() *AnonymousAuthenticationToken {
	this.Principal = "anonymousUser"
	this.Authorities = []GrantedAuthority{Authority("ROLE_ANONYMOUS")}
	this.setAuthenticated(false)
	return &this
}

// GetCredentials() implements [Authentication.GetCredentials].
func (this *AnonymousAuthenticationToken) GetCredentials() any {
	return ""
}

// RememberMeAuthenticationToken is an implementation of [Authentication] representing an user authenticated by a [RememberMeService].
type RememberMeAuthenticationToken struct {
	Key string
	AbstractAuthenticationToken
}

var _ Authentication = &RememberMeAuthenticationToken{}

// New() is the constructor for [RememberMeAuthenticationToken].
func (this RememberMeAuthenticationToken) New(key string, principal any, authorities []GrantedAuthority) *RememberMeAuthenticationToken {
	this.Key = key
	this.Principal = principal
	this.Authorities = authorities
	this.setAuthenticated(true)
	return &this
}

// GetCredentials() implements [Authentication.GetCredentials].
func (this *RememberMeAuthenticationToken) GetCredentials() any {
	return ""
}

// PreAuthenticatedAuthenticationToken is an implementation of [Authentication] representing
// a pre-authenticated principal (e.g. from upstream reverse proxy headers or TLS client certificates).
type PreAuthenticatedAuthenticationToken struct {
	credentials any
	AbstractAuthenticationToken
}

var _ Authentication = &PreAuthenticatedAuthenticationToken{}

// New() is the constructor for an unauthenticated [PreAuthenticatedAuthenticationToken].
func (this PreAuthenticatedAuthenticationToken) New(principal, credentials any) *PreAuthenticatedAuthenticationToken {
	this.setPrincipal(principal)
	this.credentials = credentials
	this.setAuthenticated(false)
	return &this
}

// NewAuthenticated() is the constructor for an authenticated [PreAuthenticatedAuthenticationToken].
func (this PreAuthenticatedAuthenticationToken) NewAuthenticated(principal, credentials any, authorities []GrantedAuthority) *PreAuthenticatedAuthenticationToken {
	this.setPrincipal(principal)
	this.credentials = credentials
	this.Authorities = authorities
	this.setAuthenticated(true)
	return &this
}

// GetCredentials() implements [Authentication.GetCredentials].
func (this *PreAuthenticatedAuthenticationToken) GetCredentials() any {
	return this.credentials
}

// EraseCredentials() implements [CredentialsContainer.EraseCredentials].
func (this *PreAuthenticatedAuthenticationToken) EraseCredentials() {
	this.credentials = nil
}

func init() {
	gob.Register(&AbstractAuthenticationToken{})
	gob.Register(&RememberMeAuthenticationToken{})
	gob.Register(&UsernamePasswordAuthenticationToken{})
	gob.Register(&PreAuthenticatedAuthenticationToken{})
}
