package testing

import (
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

type ManageableUser interface {
	UserDetails
	SetPassword(password string)
}

type UserDetailsManager interface {
	UserDetailsService
	AddUser(user ManageableUser)
}

type InMemoryUserDetailsManager struct {
	encoder PasswordEncoder
	users   []UserDetails
}

var _ UserDetailsService = &InMemoryUserDetailsManager{}

func (this InMemoryUserDetailsManager) New(encoder PasswordEncoder) *InMemoryUserDetailsManager {
	this.encoder = encoder
	return &this
}

func (this *InMemoryUserDetailsManager) NewUser() *UserBuilder[*InMemoryUserDetailsManager] {
	builder := UserBuilder[*InMemoryUserDetailsManager]{}.New(this)
	return builder
}

func (this *InMemoryUserDetailsManager) AddUser(user ManageableUser) {
	encode, err := this.encoder.Encode([]byte(user.GetPassword()))
	if err == nil {
		user.SetPassword(string(encode))
		this.users = append(this.users, user)
	}
}

func (this *InMemoryUserDetailsManager) LoadUserByUsername(username string) UserDetails {
	for _, user := range this.users {
		if user.GetUsername() == username {
			return user
		}
	}

	return nil
}
