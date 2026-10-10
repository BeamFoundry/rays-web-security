package chain

import (
	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	"github.com/timandy/routine"
)

type DefaultSecurityContext struct {
	authentication   Authentication
	policyDebugValue string
}

var _ SecurityContext = &DefaultSecurityContext{}

func (this DefaultSecurityContext) New(authentication Authentication) SecurityContext {
	this.SetAuthentication(authentication)
	return &this
}

func (this *DefaultSecurityContext) GetAuthentication() Authentication {
	return this.authentication
}

func (this *DefaultSecurityContext) SetAuthentication(authentication Authentication) {
	this.authentication = authentication
}

func (this *DefaultSecurityContext) GetHTTPPolicyDebugValue() string {
	return this.policyDebugValue
}

func (this *DefaultSecurityContext) SetHTTPPolicyDebugValue(debug string) {
	this.policyDebugValue = debug
}

type DefaultSecurityContextHolder struct {
	Service
	threadLocal routine.ThreadLocal[SecurityContext]
}

func (this *DefaultSecurityContextHolder) PostConstruct() Error {
	this.threadLocal = routine.NewThreadLocal[SecurityContext]()
	return nil
}

func (this *DefaultSecurityContextHolder) ClearContext() {
	this.threadLocal.Set(nil)
}

func (this *DefaultSecurityContextHolder) SetContext(context SecurityContext) {
	this.threadLocal.Set(context)
}

func (this *DefaultSecurityContextHolder) GetContext() SecurityContext {
	return this.threadLocal.Get()
}

var _ SecurityContextHolder = &DefaultSecurityContextHolder{}

var _, _ = any(&DefaultSecurityContextHolder{}).(Stereotype)
