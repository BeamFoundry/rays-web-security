package chain

import (
	"context"
	"encoding/gob"
	"errors"
	"io"
	"reflect"

	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/i18n"
	. "github.com/BeamFoundry/rays/pkg/lang"

	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"

	"github.com/go-playground/validator/v10"
)

type FormLoginFilter struct {
	Component
	Prototype
	SessionAwareFilter
	logger       Logging `@:"Inject"`
	httpSecurity *HttpSecurity

	authenticationManager AuthenticationManager `@:"Inject"`

	messageSourceValidator Optional[MessageSourceValidator] `@:"Inject"`
}

var _, _ = any(&FormLoginFilter{}).(Stereotype)

var _ SecurityFilter = &FormLoginFilter{}

var _ SecurityEndpointRegistration = &FormLoginFilter{}

func (this *FormLoginFilter) WithContext(ctx context.Context) Error {
	if ct := ctx.Value(PrototypeContextParentInstance); ct != nil {
		httpSecurity, ok := (ct).(*HttpSecurity)
		if !ok {
			return NewError("IllegalArgumentException", "Only HttpSecurity may inject this type")
		}
		if httpSecurity.FormLogin() == nil {
			return NewError("IllegalArgumentException", "HttpSecurity must accept FormLogin to use this filter.")
		}
		this.httpSecurity = httpSecurity
	}
	return nil
}

// RegisterSecurityEndpoint implements [SecurityEndpointRegistration].
func (this *FormLoginFilter) RegisterSecurityEndpoint(router SecurityRouter) {
	router.Get(this.httpSecurity.FormLogin().LoginPath(), func(handler SecurityHandler) error {
		this.logger.Debug("Rendering Login Form", "path", this.httpSecurity.FormLogin().LoginPath(), "view", this.httpSecurity.FormLogin().ViewName())
		return this.renderLogin(handler, map[string]any{})
	})

	router.Get(this.httpSecurity.FormLogin().LogoutPath(), func(handler SecurityHandler) error {
		handler.SessionReset()
		if rememberMe, ok := this.httpSecurity.RememberMeService().Get(); ok {
			this.logger.Debug("Setting rememberMe")
			rememberMe.Logout(handler)
		}
		url := this.httpSecurity.FormLogin().DefaultSuccessURL()
		return DefaultSecurityFilterChainException{}.RedirectTo(url).Handle(handler)
	})

	router.Post(this.httpSecurity.FormLogin().LoginPath(), func(handler SecurityHandler) error {
		fields := []reflect.StructField{
			{
				Name: "Username",
				Type: reflect.TypeFor[string](),
				Tag:  reflect.StructTag(`form:"` + this.httpSecurity.FormLogin().Username() + `" validate:"required" field:"username"`),
			},
			{
				Name: "Password",
				Type: reflect.TypeFor[string](),
				Tag:  reflect.StructTag(`form:"` + this.httpSecurity.FormLogin().Password() + `" validate:"required" field:"password`),
			},
		}

		t := reflect.StructOf(fields)
		form := reflect.New(t)
		if err := handler.BindBody(form.Interface()); err != nil {
			data := this.BindErrorMessage(form.Interface(), err)
			return this.renderLogin(handler, data)
		}
		username := form.Elem().FieldByName("Username").String()
		password := form.Elem().FieldByName("Password").String()

		err := Try(func() {
			err := this.processLogin(handler, username, password)
			this.logger.Debug("ProcessFormLogin", "err", err.Error())
			RaiseErr(err)
		}, Catch(func(ex AuthenticationException) Error {
			this.logger.Debug("Got an AuthenticationException")
			return NewErrorFrom(this.renderLogin(handler, map[string]any{"Error": ex.Error()}))
		}), Catch(func(ex SecurityFilterChainException) Error {
			this.logger.Debug("Got a SecurityFilterChainException")
			return NewErrorFrom(ex.Handle(handler))
		}),
		)
		return errors.Unwrap(err)
	})
}

func (this *FormLoginFilter) BindErrorMessage(obj any, err error) map[string]any {
	data := map[string]any{"Form": obj, "Error": err.Error()}

	var errs validator.ValidationErrors
	if errors.As(err, &errs) {
		data = map[string]any{"Form": obj, "Errors": errs.Error()}
		if messageSourceValidator, ok := this.messageSourceValidator.Get(); ok {
			data = map[string]any{"Form": obj, "Errors": messageSourceValidator.TranslateValidationErrors(errs, "fields.login")}
		}
	}
	return data
}

// Authenticate implements [SecurityFilter].
func (this *FormLoginFilter) Authenticate(_ SecurityHandler) SecurityFilterChainException {
	return DefaultSecurityFilterChainException{}.Next()
}

// AuthenticationRequired implements [SecurityFilter].
func (this *FormLoginFilter) AuthenticationRequired(handler SecurityHandler) SecurityFilterChainException {
	url := handler.Path()
	if handler.Method() != "GET" {
		url = "/"
		if this.httpSecurity.FormLogin().DefaultSuccessURL() != "" {
			url = this.httpSecurity.FormLogin().DefaultSuccessURL()
		}
	}
	handler.SetSessionValue("redirect", url)
	return DefaultSecurityFilterChainException{}.RedirectTo(this.httpSecurity.FormLogin().LoginPath())
}

func (this *FormLoginFilter) processLogin(handler SecurityHandler, username, password string) Exception {
	token := UsernamePasswordAuthenticationToken{}.New(username, password)
	auth, ex := this.authenticationManager.Authenticate(token)
	if ex != nil {
		return ex
	}
	url := this.httpSecurity.FormLogin().DefaultSuccessURL()
	if redirect, ok := handler.SessionValue("redirect").(string); ok {
		url = redirect
	}
	enc := gob.NewEncoder(io.Discard)

	// This will log an Error if enc.Encode fails. It uses RaiseNilErr to always gets an Error, to never have to test it.
	// TODO: Add TryErr. Try does not return the error, reports it?
	err := Try(
		func() {
			RaiseNilErr(enc.Encode(auth))
		},
		Catch(
			func(e Error) Error {
				e.LogError()
				return nil
			},
		),
	)

	if err == nil {
		handler.SessionRefresh()
		handler.SetSessionValue("authentication", auth)
	}

	// RememberMe cookie
	if rememberMe, ok := this.httpSecurity.RememberMeService().Get(); ok {
		this.logger.Debug("Setting rememberMe")
		rememberMe.LoginSuccess(handler, auth)
	}
	return DefaultSecurityFilterChainException{}.RedirectTo(url)
}

func (this *FormLoginFilter) renderLogin(handler SecurityHandler, m map[string]any) error {
	loginForm := struct {
		Action   string
		Username string
		Password string
	}{
		Action:   this.httpSecurity.FormLogin().LoginPath(),
		Username: this.httpSecurity.FormLogin().Username(),
		Password: this.httpSecurity.FormLogin().Password(),
	}
	m["loginForm"] = loginForm

	//nolint:wrapcheck // Not needed
	return handler.RenderView(this.httpSecurity.FormLogin().ViewName(), m)
}
