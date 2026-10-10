package chain

import (
	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"

	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

type DefaultSecurityFilterChain struct {
	Component
	logger                Logging                    `@:"Inject"`
	securityContextHolder SecurityContextHolder      `@:"Inject"`
	httpSecurity          map[string][]*HttpSecurity `@:"Inject{GroupBy=Server,Default=primary}"`
}

var _, _ = any(&DefaultSecurityFilterChain{}).(Stereotype)

var _ SecurityFilterChain = &DefaultSecurityFilterChain{}

func (this DefaultSecurityFilterChain) New() *DefaultSecurityFilterChain {
	this.httpSecurity = make(map[string][]*HttpSecurity)
	return &this
}

func (this *DefaultSecurityFilterChain) Initialize(serverName string, app SecurityAppHandler) {
	// Initialize SecurityContextHolder
	app.Use(func(handler SecurityHandler) error {
		this.securityContextHolder.ClearContext()
		anonymous := AnonymousAuthenticationToken{}.New()
		context := DefaultSecurityContext{}.New(anonymous)
		this.securityContextHolder.SetContext(context)
		return DefaultSecurityFilterChainException{}.Next().Handle(handler)
	})

	// Enable Session
	app.EnableSession(func(handler SecurityHandler) bool {
		httpSecurity := this.findHttpSecurity(serverName, handler.Path())
		switch httpSecurity.SessionCreationPolicy() {
		case SessionCreationPolicy{}.New().ALWAYS:
			return false
		case SessionCreationPolicy{}.New().IF_REQUIRED:
			if app.HasSession(handler) {
				return false
			}
			for _, filter := range httpSecurity.Filters() {
				if _, ok := (filter).(SessionAwareFilter); ok {
					return false
				}
			}
			return true
		case SessionCreationPolicy{}.New().NEVER:
			return !app.HasSession(handler)
		default:
			return true
		}
	})

	// Enable Csrf
	app.EnableCsrf(func(handler SecurityHandler) bool {
		httpSecurity := this.findHttpSecurity(serverName, handler.Path())
		return httpSecurity.Csrf().Disabled()
	})

	// Authentication
	app.Use(func(handler SecurityHandler) error {
		// Session
		if app.HasSession(handler) {
			if authentication, ok := handler.SessionValue("authentication").(Authentication); ok {
				this.logger.Debug("Got Authentication from session")
				this.securityContextHolder.GetContext().SetAuthentication(authentication)
				return DefaultSecurityFilterChainException{}.Next().Handle(handler)
			}
		}
		// RememberMe
		httpSecurity := this.findHttpSecurity(serverName, handler.Path())
		if rememberMe, ok := httpSecurity.RememberMeService().Get(); ok {
			this.logger.Trace("Found RememberMe Service")
			var authentication Authentication
			//nolint:errcheck,gocritic // Error will be nil
			Try(func() {
				authentication = RaiseVal(rememberMe.AutoLogin(handler))
			}, /* CatchName("RememberMeError", func(e Error) Error {
				e.LogError()
				return nil
			})*/
			)
			if authentication != nil {
				this.logger.Debug("RememberMe Service return an authentication")
				handler.SetSessionValue("authentication", authentication)
				this.securityContextHolder.GetContext().SetAuthentication(authentication)
				return DefaultSecurityFilterChainException{}.Next().Handle(handler)
			}
		}
		ex := this.authenticationFilter(serverName, handler)
		this.logger.Trace("Authentication returned", "action", ex.Action())
		return ex.Handle(handler)
	})

	// Authorization
	app.Use(func(handler SecurityHandler) error {
		ex := this.authorizationFilter(serverName, handler)
		app.PostAuthorizationFilter(handler)
		this.logger.Trace("Authorization returned", "action", ex.Action())
		return ex.Handle(handler)
	})

	// TODO: With a SecurityEndpointRegistration interface, only if no matchers ???
	if httpSecurities, ok := this.httpSecurity[serverName]; ok {
		for _, httpSecurity := range httpSecurities {
			for _, filter := range httpSecurity.Filters() {
				if register, ok := filter.(SecurityEndpointRegistration); ok {
					this.logger.Debug("Found a SecurityEndpointRegistration")
					register.RegisterSecurityEndpoint(app)
				}
			}
		}
	}
}

func (this *DefaultSecurityFilterChain) findHttpSecurity(serverName, path string) *HttpSecurity {
	if httpSecurities, ok := this.httpSecurity[serverName]; ok {
		for _, httpSecurity := range httpSecurities {
			for _, matcher := range httpSecurity.Matchers() {
				if matcher.MatchString(path) {
					//+ this.logger.Trace("Found an httpSecurity with a matcher for this path, using it")
					return httpSecurity
				}
			}
		}

		for _, httpSecurity := range httpSecurities {
			if len(httpSecurity.Matchers()) == 0 {
				//+ this.logger.Trace("Found an httpSecurity without any matcher, using it")
				return httpSecurity
			}
		}
	}

	this.logger.Debug("No matching httpSecurity found, creating one")
	builder := &HttpSecurityBuilder{}
	builder.AnyRequest().PermitAll()
	return builder.Build()
}

func (this *DefaultSecurityFilterChain) authenticationFilter(serverName string, handler SecurityHandler) SecurityFilterChainException {
	httpSecurity := this.findHttpSecurity(serverName, handler.Path())
	filters := httpSecurity.Filters()
	for _, filter := range filters {
		ex := filter.Authenticate(handler)
		if ex.Action() != (DefaultSecurityFilterAction{}.New()).NEXT.Name() {
			return ex
		}
		if this.securityContextHolder.GetContext().GetAuthentication().IsAuthenticated() {
			break
		}
	}
	return DefaultSecurityFilterChainException{}.Next()
}

func (this *DefaultSecurityFilterChain) authorizationFilter(serverName string, handler SecurityHandler) SecurityFilterChainException {
	var ex SecurityFilterChainException
	switch {
	case this.allow(serverName, handler):
		ex = DefaultSecurityFilterChainException{}.Next()
	case this.securityContextHolder.GetContext().GetAuthentication().IsAuthenticated():
		ex = DefaultSecurityFilterChainException{}.ReportError(NewError("HttpException", "Unauthorized"), 403)
	default:
		// TODO: Maybe retry each filters to authenticate and if one returns an error
		// use the corresponding AuthenticationRequired method, or the last one if all returns next.
		httpSecurity := this.findHttpSecurity(serverName, handler.Path())
		filters := httpSecurity.Filters()
		ex = filters[len(filters)-1].AuthenticationRequired(handler)
	}
	return ex
}

func (this *DefaultSecurityFilterChain) getAuthorizedHttpRequest(serverName string, handler SecurityHandler) *AuthorizedHttpRequest {
	httpSecurity := this.findHttpSecurity(serverName, handler.Path())
	for _, request := range httpSecurity.AuthorizedHTTPRequests() {
		if request.Matcher().Match(handler.Method(), handler.Path()) {
			this.securityContextHolder.GetContext().SetHTTPPolicyDebugValue("MATCHER:" + request.Matcher().String() + " POLICY:" + request.Policy().String())
			return request
		}
	}
	return nil
}

func (this *DefaultSecurityFilterChain) getDefaultHttpPolicy(serverName string, handler SecurityHandler) *HttpPolicy {
	httpSecurity := this.findHttpSecurity(serverName, handler.Path())
	this.securityContextHolder.GetContext().SetHTTPPolicyDebugValue("POLICY:" + httpSecurity.DefaultHTTPPolicy().String())
	return httpSecurity.DefaultHTTPPolicy()
}

func (this *DefaultSecurityFilterChain) allow(serverName string, handler SecurityHandler) bool {
	auth := this.securityContextHolder.GetContext().GetAuthentication()
	if request := this.getAuthorizedHttpRequest(serverName, handler); request != nil {
		if request.Policy().Allow(auth) {
			this.logger.Trace("Policy Allow", "method", handler.Method(), "path", handler.Path(), "policy", request.Policy(), "matcher", request.Matcher())
			return true
		}
		this.logger.Trace("Policy Deny", "method", handler.Method(), "path", handler.Path(), "policy", request.Policy())
		return false
	}
	policy := this.getDefaultHttpPolicy(serverName, handler)
	if policy.Allow(auth) {
		this.logger.Trace("Default Policy Allow", "method", handler.Method(), "path", handler.Path(), "policy", policy)
		return true
	}
	this.logger.Trace("Default Policy Deny", "method", handler.Method(), "path", handler.Path(), "policy", policy)
	return false
}
