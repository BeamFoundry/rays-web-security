package testing

import (
	"encoding/gob"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

type InMemoryUser struct {
	Username           string
	Password           string
	Authorities        []GrantedAuthority
	AccountExpired     bool
	CredentialsExpired bool
	Disabled           bool
	Locked             bool
}

func (this *InMemoryUser) GetUsername() string                { return this.Username }
func (this *InMemoryUser) GetPassword() string                { return this.Password }
func (this *InMemoryUser) GetAuthorities() []GrantedAuthority { return this.Authorities }
func (this *InMemoryUser) IsExpired() bool                    { return this.AccountExpired }
func (this *InMemoryUser) IsCredentialExpired() bool          { return this.CredentialsExpired }
func (this *InMemoryUser) IsDisabled() bool                   { return this.Disabled }
func (this *InMemoryUser) IsLocked() bool                     { return this.Locked }
func (this *InMemoryUser) SetPassword(password string)        { this.Password = password }

type UserBuilder[B UserDetailsManager] struct {
	manager B
	user    *InMemoryUser
}

func (this UserBuilder[B]) New(manager B) *UserBuilder[B] {
	this.manager = manager
	this.user = &InMemoryUser{}
	return &this
}

func (this *UserBuilder[B]) WithUsername(username string) *UserBuilder[B] {
	this.user.Username = username
	return this
}

func (this *UserBuilder[B]) WithPassword(password string) *UserBuilder[B] {
	this.user.Password = password
	return this
}

func (this *UserBuilder[B]) WithAuthorities(authorities []GrantedAuthority) *UserBuilder[B] {
	this.user.Authorities = authorities
	return this
}

func (this *UserBuilder[B]) SetAccountExpired(expired bool) *UserBuilder[B] {
	this.user.AccountExpired = expired
	return this
}

func (this *UserBuilder[B]) SetCredentialsExpired(expired bool) *UserBuilder[B] {
	this.user.CredentialsExpired = expired
	return this
}

func (this *UserBuilder[B]) SetDisabled(disabled bool) *UserBuilder[B] {
	this.user.Disabled = disabled
	return this
}

func (this *UserBuilder[B]) SetLocked(locked bool) *UserBuilder[B] {
	this.user.Locked = locked
	return this
}

func (this *UserBuilder[B]) Build() UserDetails {
	this.manager.AddUser(this.user)
	return this.user
}

func init() {
	gob.Register(&InMemoryUser{})
}
