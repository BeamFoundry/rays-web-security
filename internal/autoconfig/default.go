package autoconfig

import (
	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"

	_ "github.com/BeamFoundry/rays-web-security/internal/chain" // Required

	. "github.com/BeamFoundry/rays-web-security/internal/manager"

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
	return DelegatingPasswordEncoder{}.New(
		"bcrypt", map[string]PasswordEncoder{"bcrypt": BCryptPasswordEncoder{}.New(10)},
	)
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
