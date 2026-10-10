package manager

import (
	"reflect"

	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"

	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

type UserDetailsAuthenticationProvider struct {
	service UserDetailsService
	encoder PasswordEncoder
	// logger  logging.Logging `@:"Inject"`
}

var _ AuthenticationProvider = &UserDetailsAuthenticationProvider{}

func (this UserDetailsAuthenticationProvider) New(service UserDetailsService) *UserDetailsAuthenticationProvider {
	this.service = service
	return &this
}

func (this *UserDetailsAuthenticationProvider) SetEncoder(encoder PasswordEncoder) {
	this.encoder = encoder
}

func (this *UserDetailsAuthenticationProvider) Supports(authentication Authentication) bool {
	return reflect.TypeOf(authentication) == reflect.TypeFor[*UsernamePasswordAuthenticationToken]()
}

func (this *UserDetailsAuthenticationProvider) Authenticate(authentication Authentication) (Authentication, AuthenticationException) {
	token := authentication.(*UsernamePasswordAuthenticationToken)

	// TODO: This check should be removed. Is it tested ??? (Remove test)
	if !reflect.ValueOf(this.service).IsValid() {
		return nil, InternalAuthenticationException{}.New("UserDetailsService is not available", authentication)
	}

	if user := this.service.LoadUserByUsername(token.GetPrincipal().(string)); user == nil {
		return nil, BadCredentialsException{}.New("UserDetailAuthenticationProvider: Bad credentials", authentication)
	} else {
		err := Try(
			func() {
				_ = user.IsExpired() && RaiseErr(AccountExpiredException{}.New("UserDetailsService: User is expired", authentication))
				_ = user.IsCredentialExpired() && RaiseErr(CredentialsExpiredException{}.New("UserDetailsService: User credentials have expired", authentication))
				_ = user.IsLocked() && RaiseErr(LockedException{}.New("UserDetailsService: User is locked", authentication))
				_ = user.IsDisabled() && RaiseErr(DisabledException{}.New("UserDetailsService: User is disabled", authentication))

				if !this.encoder.Matches([]byte(token.GetCredentials().(string)), []byte(user.GetPassword())) {
					RaiseErr(BadCredentialsException{}.New("UserDetailAuthenticationProvider: Bad credentials", authentication))
				}

				authentication = UsernamePasswordAuthenticationToken{}.NewAuthenticated(user, "", user.GetAuthorities())
			},
			Catch(func(err AuthenticationException) Error {
				return err
			}),
			/*
				Catch(func(err Error) Error {
					//this.logger.Debug("UserDetailsAuthenticationProvider:Error", "err", err)
					return InternalAuthenticationException{}.New(err.Message())
				}),
			*/
		)
		if exception, ok := err.(AuthenticationException); ok {
			return authentication, exception
		}
	}
	token.EraseCredentials()
	return authentication, nil
}

type AnonymousAuthenticationProvider struct {
	Component
}

var _ AuthenticationProvider = &AnonymousAuthenticationProvider{}

var _, _ = any(&AnonymousAuthenticationProvider{}).(Stereotype)

func (this *AnonymousAuthenticationProvider) Supports(authentication Authentication) bool {
	return reflect.TypeOf(authentication) == reflect.TypeFor[*AnonymousAuthenticationToken]()
}

func (this *AnonymousAuthenticationProvider) Authenticate(authentication Authentication) (Authentication, AuthenticationException) {
	return authentication, nil
}

type RememberMeAuthenticationProvider struct {
	Component
}

var _ AuthenticationProvider = &RememberMeAuthenticationProvider{}

var _, _ = any(&RememberMeAuthenticationProvider{}).(Stereotype)

func (this *RememberMeAuthenticationProvider) Supports(authentication Authentication) bool {
	return reflect.TypeOf(authentication) == reflect.TypeFor[*RememberMeAuthenticationToken]()
}

func (this *RememberMeAuthenticationProvider) Authenticate(authentication Authentication) (Authentication, AuthenticationException) {
	return authentication, nil
}
