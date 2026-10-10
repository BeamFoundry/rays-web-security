package config

import (
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// SessionCreationPolicyEnum is an Enum type representing a SessionCreationPolicy.
type SessionCreationPolicyEnum struct {
	IF_REQUIRED,
	ALWAYS,
	NEVER,
	STATELESS SessionCreationPolicy
}

// SessionCreationPolicy is an Enum alias for SessionCreationPolicyEnum.
type SessionCreationPolicy = Enum[SessionCreationPolicyEnum]

// SessionCreationPolicyConfigurer lets you configure the [SessionCreationPolicy] in an [HttpSecurityBuilder].
type SessionCreationPolicyConfigurer struct {
	next *HttpSecurityBuilder
}

func (this SessionCreationPolicyConfigurer) newConfigurer(httpSecurityBuilder *HttpSecurityBuilder) *SessionCreationPolicyConfigurer {
	this.next = httpSecurityBuilder
	return &this
}

// Default() configure the [HttpSecurityBuilder] with the default [SessionCreationPolicy]
//
// Default : [SessionCreationPolicyEnum.IF_REQUIRED].
func (this *SessionCreationPolicyConfigurer) Default() *HttpSecurityBuilder {
	this.next.httpSecurity.session = SessionCreationPolicy{}.New().IF_REQUIRED
	return this.next
}

// Always() configure the [HttpSecurityBuilder] with the [SessionCreationPolicyEnum.ALWAYS].
//
// In this mode Rays will always create a Session.
func (this *SessionCreationPolicyConfigurer) Always() *HttpSecurityBuilder {
	this.next.httpSecurity.session = SessionCreationPolicy{}.New().ALWAYS
	return this.next
}

// IfRequired() configure the [HttpSecurityBuilder] with the [SessionCreationPolicyEnum.IF_REQUIRED].
//
// In this mode Rays will create a Session only if required.
func (this *SessionCreationPolicyConfigurer) IfRequired() *HttpSecurityBuilder {
	this.next.httpSecurity.session = SessionCreationPolicy{}.New().IF_REQUIRED
	return this.next
}

// Never() configure the [HttpSecurityBuilder] with the [SessionCreationPolicyEnum.NEVER].
//
// In this mode Rays will never create a Session but will use one if it already exists.
func (this *SessionCreationPolicyConfigurer) Never() *HttpSecurityBuilder {
	this.next.httpSecurity.session = SessionCreationPolicy{}.New().NEVER
	return this.next
}

// Stateless() configure the [HttpSecurityBuilder] with the [SessionCreationPolicyEnum.STATELESS].
//
// In this mode Rays will not configure a Session.
func (this *SessionCreationPolicyConfigurer) Stateless() *HttpSecurityBuilder {
	this.next.httpSecurity.session = SessionCreationPolicy{}.New().STATELESS
	return this.next
}
