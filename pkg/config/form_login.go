package config

type FormLogin struct {
	username          string
	password          string
	loginPath         string
	logoutPath        string
	viewName          string
	defaultSuccessURL string
}

//nolint:gocritic // Constructor.
func (this FormLogin) newFormLogin() *FormLogin {
	this.username = "username"
	this.password = "password"
	this.loginPath = "/login"
	this.logoutPath = "/logout"
	this.viewName = "login"
	this.defaultSuccessURL = "/"
	return &this
}

// Username() returns the HTML form field name for this [FormLogin] that provide the user's username.
//
// Defaults to "username".
func (this *FormLogin) Username() string {
	return this.username
}

// Password() returns the HTML form field name or this [FormLogin] that provide the user's password.
//
// Defaults to "password".
func (this *FormLogin) Password() string {
	return this.password
}

// LoginPath() returns the login path this [FormLogin] will register the login hook.
//
// Defaults to "/login".
func (this *FormLogin) LoginPath() string {
	return this.loginPath
}

// LogoutPath() returns the logout path this [FormLogin] will register the logout hook.
//
// Defaults to "/logout".
func (this *FormLogin) LogoutPath() string {
	return this.logoutPath
}

// ViewName() returns the configured view name that will be rendered to provide the login form.
//
// Defaults to "login".
func (this *FormLogin) ViewName() string {
	return this.viewName
}

// DefaultSuccessURL() returns the defaults URL to redirect to if no alternative can be found
// upon successful login.
//
// NOTE: the last visited URL requiring an authentication and redirected to the login form, will be
// save in the session, and be used if found.
//
// Defaults to "/".
func (this *FormLogin) DefaultSuccessURL() string {
	return this.defaultSuccessURL
}

// FormLoginConfigurer lets you configure a FormLogin object in a [HttpSecurityBuilder].
type FormLoginConfigurer struct {
	next *HttpSecurityBuilder
}

func (this FormLoginConfigurer) newConfigurer(httpSecurityBuilder *HttpSecurityBuilder) *FormLoginConfigurer {
	this.next = httpSecurityBuilder
	this.next.httpSecurity.formLogin = FormLogin{}.newFormLogin()
	return &this
}

// Username() lets you configure [FormLogin.Username].
func (this *FormLoginConfigurer) Username(username string) *FormLoginConfigurer {
	this.next.httpSecurity.formLogin.username = username
	return this
}

// Password() lets you configure [FormLogin.Password].
func (this *FormLoginConfigurer) Password(password string) *FormLoginConfigurer {
	this.next.httpSecurity.formLogin.password = password
	return this
}

// LoginPath() lets you configure [FormLogin.LoginPath].
func (this *FormLoginConfigurer) LoginPath(loginPath string) *FormLoginConfigurer {
	this.next.httpSecurity.formLogin.loginPath = loginPath
	return this
}

// LogoutPath() lets you configure [FormLogin.LogoutPath].
func (this *FormLoginConfigurer) LogoutPath(logoutPath string) *FormLoginConfigurer {
	this.next.httpSecurity.formLogin.logoutPath = logoutPath
	return this
}

// ViewName() lets you configure [FormLogin.ViewName].
func (this *FormLoginConfigurer) ViewName(viewName string) *FormLoginConfigurer {
	this.next.httpSecurity.formLogin.viewName = viewName
	return this
}

// DefaultSuccessUrl() lets you configure [FormLogin.DefaultSuccessUrl].
func (this *FormLoginConfigurer) DefaultSuccessUrl(defaultSuccessUrl string) *FormLoginConfigurer {
	this.next.httpSecurity.formLogin.defaultSuccessURL = defaultSuccessUrl
	return this
}

// And() lets you return to [HttpSecurityBuilder].
func (this *FormLoginConfigurer) And() *HttpSecurityBuilder {
	return this.next
}
