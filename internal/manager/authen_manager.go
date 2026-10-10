package manager

import (
	"reflect"

	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"

	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

type AuthenticationProviderManager struct {
	Service
	Manager
	logger    Logging                  `@:"Inject"`
	providers []AuthenticationProvider `@:"Inject"`
}

var _ AuthenticationManager = &AuthenticationProviderManager{}

var _, _ = any(&AuthenticationProviderManager{}).(Stereotype)

func (this *AuthenticationProviderManager) Authenticate(authentication Authentication) (Authentication, AuthenticationException) {
	var err Error
	for _, p := range this.providers {
		if !p.Supports(authentication) {
			this.logger.Trace("AuthenticationProviderManager : Unsupported provider for authentication type", "provider", reflect.TypeOf(p), "authentication", reflect.TypeOf(authentication))
			continue
		}
		this.logger.Debug("Supported provider", "type", reflect.TypeOf(p))
		err = Try(
			func() {
				authentication = RaiseVal(p.Authenticate(authentication))
				this.logger.Trace("Successful", "Authentication", authentication)
			},
			Catch(func(err AccountStatusException) Error {
				this.logger.Error("AccountStatusException", "message", err.Error())
				return err
			}),
			Catch(func(err AuthenticationException) Error {
				this.logger.Error("AuthenticationException", "message", err.Error())
				return err
			}),
			Catch(func(err Error) Error {
				return InternalAuthenticationException{}.New("An unknown authentication error occurred: "+err.Message(), authentication)
			}),
		)

		if exception, ok := err.(AuthenticationException); ok {
			return authentication, exception
		}
		return authentication, nil
	}
	return authentication, ProviderNotFoundException{}.New("Not able to find an AuthenticationProvider to validate this Authentication", authentication)
}
