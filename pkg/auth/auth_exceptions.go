package auth

import (
	. "github.com/BeamFoundry/rays/pkg/lang"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

// AuthenticationError is a base Error for reporting authentication error as an [AuthenticationException]
type authenticationError struct {
	*DefaultError
	authentication Authentication
}

// ) () implements [AuthenticationException.) ].
func (this *authenticationError) AuthenticationRequest() Authentication {
	return this.authentication
}

func (this *authenticationError) setAuthenticationRequest(authentication Authentication) {
	this.authentication = authentication
}

// InternalAuthenticationException is the fallthrough [AuthenticationException] returned in case of
// a problem in the aurthentication process.
type InternalAuthenticationException struct {
	authenticationError
}

// New() create a new [InternalAuthenticationException] with the provided message.
func (this InternalAuthenticationException) New(message string, authentication Authentication) *InternalAuthenticationException {
	this.DefaultError = NewError("InternalAuthenticationExceptionException", message)
	this.setAuthenticationRequest(authentication)
	return &this
}

var _ AuthenticationException = &InternalAuthenticationException{}

// BadCredentialsException is an [AuthenticationException] used to report an authentication error
// resulted from an incorrect authentication credentials.
type BadCredentialsException struct {
	authenticationError
}

// New() create a new [BadCredentialsException] with the provided message
func (this BadCredentialsException) New(msg string, authentication Authentication) *BadCredentialsException {
	this.DefaultError = NewError("BadCredentialsException", msg)
	this.setAuthenticationRequest(authentication)
	return &this
}

var _ AuthenticationException = &BadCredentialsException{}

// ProviderNotFoundException is an [AuthenticationException] used to report if no [AuthenticationProvider] could be found
// by the [AuthenticationManager].
type ProviderNotFoundException struct {
	authenticationError
}

// New() creates a new [ProviderNotFoundException] with the provided message.
func (this ProviderNotFoundException) New(msg string, authentication Authentication) *ProviderNotFoundException {
	this.DefaultError = NewError("ProviderNotFoundException", msg)
	this.setAuthenticationRequest(authentication)
	return &this
}

var _ AuthenticationException = &ProviderNotFoundException{}

// AccountStatusExceptionCauseEnum is a Enum type representing a separate reason an account may not
// be valid.
type AccountStatusExceptionCauseEnum struct {
	ACCOUNT_EXPIRED,
	CREDENTIALS_EXPIRED,
	DISABLED,
	LOCKED AccountStatusExceptionCause
}

// AccountStatusExceptionCause is an Enum alias for [AccountStatusExceptionCauseEnum]
type AccountStatusExceptionCause = Enum[AccountStatusExceptionCauseEnum]

// AccountStatusException is a specialized [AuthenticationException] interface used to describe that an account may not me valid.
type AccountStatusException interface {
	AuthenticationException
	AccountStatus() AccountStatusExceptionCause
}

// AccountStatusError is the base implementation of [AccountStatusException].
type accountStatusError struct {
	authenticationError
	cause AccountStatusExceptionCause
}

// NewAccountStatusError() is the constructor for [AccountStatusError].
/*
func (this accountStatusError) NewAccountStatusError(name, message string, cause AccountStatusExceptionCause) *accountStatusError {
	this.DefaultError = NewError(name, message)
	this.cause = cause
	return &this
}
*/

// AccountStatus() implements [AccountStatusException.AccountStatus].
func (this *accountStatusError) AccountStatus() AccountStatusExceptionCause {
	return this.cause
}

// AccountExpiredException is an [AccountStatusException] used to describe an [AuthenticationError]
// raised when an account is marked as expired.
type AccountExpiredException struct {
	accountStatusError
}

var _ AccountStatusException = &AccountExpiredException{}

// New() is the constructor for [AccountExpiredException].
func (this AccountExpiredException) New(message string, authentication Authentication) *AccountExpiredException {
	this.DefaultError = NewError("AccountExpiredException", message)
	this.cause = AccountStatusExceptionCause{}.New().ACCOUNT_EXPIRED
	this.setAuthenticationRequest(authentication)
	return &this
}

// CredentialsExpiredException is an [AccountStatusException] used to describe an [AuthenticationError]
// raised when an account credentials is marked as expired.
type CredentialsExpiredException struct {
	accountStatusError
}

var _ AccountStatusException = &CredentialsExpiredException{}

// New() is the constructor for [CredentialsExpiredException].
func (this CredentialsExpiredException) New(message string, authentication Authentication) *CredentialsExpiredException {
	this.DefaultError = NewError("CredentialsExpiredException", message)
	this.cause = AccountStatusExceptionCause{}.New().CREDENTIALS_EXPIRED
	this.setAuthenticationRequest(authentication)
	return &this
}

// AccountExpiredException is an [AccountStatusException] used to describe an [AuthenticationError]
// raised when an account is marked as disabled.
type DisabledException struct {
	accountStatusError
}

var _ AccountStatusException = &DisabledException{}

// New() is the constructor for [DisabledException].
func (this DisabledException) New(message string, authentication Authentication) *DisabledException {
	this.DefaultError = NewError("DisabledException", message)
	this.cause = AccountStatusExceptionCause{}.New().DISABLED
	this.setAuthenticationRequest(authentication)
	return &this
}

// AccountExpiredException is an [AccountStatusException] used to describe an [AuthenticationError]
// raised when an account is marked as locked.
type LockedException struct {
	accountStatusError
}

var _ AccountStatusException = &LockedException{}

// New() is the constructor for [LockedException].
func (this LockedException) New(message string, authentication Authentication) *LockedException {
	this.DefaultError = NewError("LockedException", message)
	this.cause = AccountStatusExceptionCause{}.New().LOCKED
	this.setAuthenticationRequest(authentication)
	return &this
}

//----
