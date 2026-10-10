package filter

import (
	"encoding/base64"
	"encoding/gob"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"

	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
	. "github.com/BeamFoundry/rays/pkg/logging"
	. "github.com/BeamFoundry/rays/pkg/web"

	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"

	"github.com/go-playground/validator/v10"
)

type UsernamePasswordAuthenticationFilter struct {
	Component
	logger                 Logging                           `@:"Inject"`
	authenticationManager  AuthenticationManager             `@:"Inject"`
	securityContextHolder  SecurityContextHolder             `@:"Inject"`
	httpSecurity           map[string][]*HttpSecurity        `@:"Inject{GroupBy=Server,Default=primary}"`
	rememberMe             Optional[RememberMeService]       `@:"Inject"`
	messageSourceValidator Optional[*MessageSourceValidator] `@:"Inject"`
}

var _ SecurityFilterAdapter = &UsernamePasswordAuthenticationFilter{}

var _, _ = any(&UsernamePasswordAuthenticationFilter{}).(Stereotype)

func (this *UsernamePasswordAuthenticationFilter) Register(app SecurityRouter, serverName string) {
	if httpSecurities, ok := this.httpSecurity[serverName]; ok {
		for _, httpSecurity := range httpSecurities {
			if formLogin := httpSecurity.FormLogin(); formLogin != nil {
				this.logger.Debug("Setting Login", "path", formLogin.LoginPath(), "view", formLogin.ViewName())

				app.Get(formLogin.LoginPath(), func(handler SecurityHandler) error {
					return this.renderLogin(handler, formLogin, map[string]any{})
				})

				app.Get(formLogin.LogoutPath(), func(handler SecurityHandler) error {
					handler.SessionReset()
					url := formLogin.DefaultSuccessURL()
					return handler.HandleSecurityFilterChainException(SecurityFilterChainError{}.RedirectTo(url))
				})

				app.Post(formLogin.LoginPath(), func(handler SecurityHandler) error {
					fields := []reflect.StructField{
						{
							Name: "Username",
							Type: reflect.TypeFor[string](),
							Tag:  reflect.StructTag(`form:"` + formLogin.Username() + `" validate:"required" field:"username"`),
						},
						{
							Name: "Password",
							Type: reflect.TypeFor[string](),
							Tag:  reflect.StructTag(`form:"` + formLogin.Password() + `" validate:"required" field:"password`),
						},
					}

					t := reflect.StructOf(fields)
					form := reflect.New(t)
					if err := handler.BindBody(form.Interface()); err != nil {
						data := this.BindErrorMessage(form.Interface(), err)
						return this.renderLogin(handler, formLogin, data)
					}
					username := form.Elem().FieldByName("Username").String()
					password := form.Elem().FieldByName("Password").String()

					err := Try(func() {
						err := this.ProcessFormLogin(handler, username, password)
						this.logger.Debug("ProcessFormLogin", "err", err.Error())
						RaiseErr(err)
					}, Catch(func(ex AuthenticationException) Error {
						this.logger.Debug("Got an AuthenticationException")
						return NewErrorFrom(this.renderLogin(handler, formLogin, map[string]any{"Error": ex.Error()}))
					}), Catch(func(ex SecurityFilterChainException) Error {
						this.logger.Debug("Got a SecurityFilterChainException")
						return NewErrorFrom(handler.HandleSecurityFilterChainException(ex))
					}),
					)
					return errors.Unwrap(err)
				})
			}
		}
	}
}

func (this *UsernamePasswordAuthenticationFilter) BindErrorMessage(obj any, err error) map[string]any {
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

func (this *UsernamePasswordAuthenticationFilter) Chain() bool {
	httpSecurity := this.securityContextHolder.GetContext().GetHTTPSecurity()
	return httpSecurity.FormLogin() != nil || httpSecurity.Basic()
}

func (this *UsernamePasswordAuthenticationFilter) AuthenticationFilter(handler SecurityHandler) SecurityFilterChainException {
	httpSecurity := this.securityContextHolder.GetContext().GetHTTPSecurity()
	next := SecurityFilterChainError{}.Next()
	if httpSecurity.FormLogin() != nil {
		if authentication, ok := handler.SessionValue("authentication").(Authentication); ok {
			this.logger.Debug("Got Authentication from session")
			this.securityContextHolder.GetContext().SetAuthentication(authentication)
			return next
		}
		if rememberMe, ok := this.rememberMe.Get(); ok && httpSecurity.RememberMe() != nil {
			this.logger.Debug("Found RememberMe Service")
			var authentication Authentication
			//nolint:errcheck // Error will be nil
			Try(func() {
				authentication = RaiseVal(rememberMe.AutoLogin(handler))
			}, Catch(func(e Error) Error {
				e.LogError()
				return nil
			}))
			if authentication == nil {
				return next
			}
			this.logger.Debug("RememberMe Service return an authentication")
			handler.SetSessionValue("authentication", authentication)
			this.securityContextHolder.GetContext().SetAuthentication(authentication)
			return next
		}
	} else if httpSecurity.Basic() {
		header := handler.Header("Authorization")
		if header == "" {
			return next
		} else if len(header) <= 6 || !String(header[:6]).ToLowerCase().Equals("basic ") {
			err := NewError("IllegalArgumentException", "'Authorization' header must start with 'Basic'")
			return SecurityFilterChainError{}.ReportError(err, http.StatusBadRequest)
		}
		raw, err := base64.StdEncoding.DecodeString(header[6:])
		if err != nil {
			return SecurityFilterChainError{}.ReportError(NewError("IllegalArgumentException", err.Error()), http.StatusBadRequest)
		}
		creds := unsafeString(raw)
		before, after, ok := strings.Cut(creds, ":")
		if !ok {
			err := NewError("IllegalArgumentException", "'Authorization' must contain Base64 encoded, separated by colon, username and password")
			return SecurityFilterChainError{}.ReportError(err, http.StatusBadRequest)
		}
		username := before
		password := after
		token := UsernamePasswordAuthenticationToken{}.New(username, password)
		authentication, err := this.authenticationManager.Authenticate(token)
		if err != nil {
			return SecurityFilterChainError{}.SetStatus(401)
		}
		this.securityContextHolder.GetContext().SetAuthentication(authentication)
	}
	return next
}

// TODO: Change that to a last Filter handle (only done for the last Filter is none passed)
func (this *UsernamePasswordAuthenticationFilter) AuthorizationFilter(handler SecurityHandler) SecurityFilterChainException {
	httpSecurity := this.securityContextHolder.GetContext().GetHTTPSecurity()
	ex := SecurityFilterChainError{}.Next()
	switch {
	case httpSecurity.FormLogin() != nil:
		url := handler.Path()
		if handler.Method() != "GET" {
			url = "/"
			if httpSecurity.FormLogin().DefaultSuccessURL() != "" {
				url = httpSecurity.FormLogin().DefaultSuccessURL()
			}
		}
		handler.SetSessionValue("redirect", url)
		ex = SecurityFilterChainError{}.RedirectTo(httpSecurity.FormLogin().LoginPath())
	case httpSecurity.Basic():
		handler.SetHeader("WWW-Authenticate", "basic realm="+"Restricted")
		ex = SecurityFilterChainError{}.SetStatus(401)
	default:
	}
	return ex
}

func (this *UsernamePasswordAuthenticationFilter) ProcessFormLogin(handler SecurityHandler, username, password string) Exception {
	httpSecurity := this.securityContextHolder.GetContext().GetHTTPSecurity()
	token := UsernamePasswordAuthenticationToken{}.New(username, password)
	auth, ex := this.authenticationManager.Authenticate(token)
	if ex != nil {
		return ex
	}
	url := this.getFormLogin().DefaultSuccessURL()
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
		handler.SessionReset()
		handler.SetSessionValue("authentication", auth)
	}

	// RememberMe cookie
	if rememberMe, ok := this.rememberMe.Get(); ok && httpSecurity.RememberMe() != nil {
		this.logger.Debug("Setting rememberMe")
		rememberMe.LoginSuccess(handler, auth)
	}
	return SecurityFilterChainError{}.RedirectTo(url)
}

func (this *UsernamePasswordAuthenticationFilter) getHttpSecurity() *HttpSecurity {
	return this.securityContextHolder.GetContext().GetHTTPSecurity()
}

func (this *UsernamePasswordAuthenticationFilter) getFormLogin() *FormLogin {
	return this.getHttpSecurity().FormLogin()
}

func (this *UsernamePasswordAuthenticationFilter) renderLogin(handler SecurityHandler, form *FormLogin, m map[string]any) error {
	loginForm := struct {
		Action   string
		Username string
		Password string
	}{
		Action:   form.LoginPath(),
		Username: form.Username(),
		Password: form.Password(),
	}
	m["loginForm"] = loginForm
	view := form.ViewName()

	//nolint:wrapcheck // Not needed
	return handler.HandleSecurityFilterChainException(SecurityFilterChainError{}.RenderView(view, m))
}
