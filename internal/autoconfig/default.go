package autoconfig

import (
	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"

	_ "github.com/BeamFoundry/rays-web-security/internal/chain" // Required

	. "github.com/BeamFoundry/rays-web-security/internal/manager"

	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/password"
)

type DefaultConfiguration struct {
	Configuration
}

var _, _ = any(&DefaultConfiguration{}).(Stereotype)

func (this *DefaultConfiguration) PasswordEncoder(
	_ struct {
		ConditionalOnMissingBeam
	},
) PasswordEncoder {
	return DelegatingPasswordEncoder{}.NewDefault()
}

func (this *DefaultConfiguration) UserDetailsAuthenticationProvider(
	that struct {
		ConditionalOnMissingBeam
		encoder PasswordEncoder              `@:"Inject"`
		service Optional[UserDetailsService] `@:"Inject"`
	},
) *UserDetailsAuthenticationProvider {
	service, ok := that.service.Get()
	if !ok {
		return nil
	}
	provider := UserDetailsAuthenticationProvider{}.New(service)
	provider.SetEncoder(that.encoder)
	return provider
}

func (this *DefaultConfiguration) AuthenticationUserDetailsService(
	that struct {
		ConditionalOnMissingBeam
		userDetailsService Optional[UserDetailsService] `@:"Inject"`
	},
) AuthenticationUserDetailsService {
	if uds, ok := that.userDetailsService.Get(); ok {
		return UserDetailsByNameServiceWrapper{}.New(uds)
	}
	return PreAuthenticatedGrantedAuthoritiesUserDetailsService{}.New()
}

func (this *DefaultConfiguration) PreAuthenticatedAuthenticationProvider(
	that struct {
		ConditionalOnMissingBeam
		service Optional[AuthenticationUserDetailsService] `@:"Inject"`
	},
) *PreAuthenticatedAuthenticationProvider {
	service, ok := that.service.Get()
	if !ok {
		return nil
	}
	return PreAuthenticatedAuthenticationProvider{}.New(service)
}
