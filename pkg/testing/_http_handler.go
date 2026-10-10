package testing

import (
	"errors"
	"net/http"
	"net/url"

	. "github.com/BeamFoundry/rays/pkg/web"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

type MockHTTPHandler struct {
	cookie map[string]*http.Cookie
	form,
	header map[string]string
	session map[string]any
	url     *url.URL
	method  HttpMethod
}

func (this MockHTTPHandler) New(method HttpMethod, u *url.URL) *MockHTTPHandler {
	this.cookie = map[string]*http.Cookie{}
	this.form = map[string]string{}
	this.header = map[string]string{}
	this.session = map[string]any{}

	this.SetMethod(method)
	this.SetURL(u)
	return &this
}

func (this *MockHTTPHandler) SetMethod(method HttpMethod) {
	this.method = method
}

func (this *MockHTTPHandler) SetURL(u *url.URL) {
	this.url = u
}

func (this *MockHTTPHandler) Cookie(name string) (*http.Cookie, error) {
	if cookie, ok := this.cookie[name]; ok {
		return cookie, nil
	}
	return nil, errors.New("Cookie not found")
}

func (this *MockHTTPHandler) FormValue(name string) string {
	if form, ok := this.form[name]; ok {
		return form
	}
	return ""
}

func (this *MockHTTPHandler) Header(name string) string {
	if header, ok := this.header[name]; ok {
		return header
	}
	return ""
}

func (this *MockHTTPHandler) Method() string {
	return this.method.String()
}

func (this *MockHTTPHandler) Path() string {
	return this.url.EscapedPath()
}

func (this *MockHTTPHandler) SessionReset() {
	this.session = map[string]any{}
}

func (this *MockHTTPHandler) SessionValue(key string) any {
	if session, ok := this.session[key]; ok {
		return session
	}
	return ""
}

func (this *MockHTTPHandler) SetCookie(cookie *http.Cookie) {
	this.cookie[cookie.Name] = cookie
}

func (this *MockHTTPHandler) SetHeader(name, value string) {
	this.header[name] = value
}

func (this *MockHTTPHandler) SetFormValue(name, value string) {
	this.form[name] = value
}

func (this *MockHTTPHandler) SetSessionValue(key string, obj any) {
	this.session[key] = obj
}

func (this *MockHTTPHandler) URL() *url.URL {
	return this.url
}

func (this *MockHTTPHandler) SetBody() {}

// BindBody implements [core.SecurityHandler].
func (this *MockHTTPHandler) BindBody(obj any) error {
	return nil
}

// HandleSecurityFilterChainException implements [core.SecurityHandler].
func (this *MockHTTPHandler) HandleSecurityFilterChainException(ex SecurityFilterChainException) error {
	return nil
}

// Render implements [core.SecurityHandler].
func (this *MockHTTPHandler) Render(view string, data map[string]any) error {
	return nil
}

// Next implements [core.SecurityHandler].
func (this *MockHTTPHandler) Next() error {
	return nil
}

func (this *MockHTTPHandler) Write(p []byte) (n int, err error) {
	return 0, nil
}

var _ SecurityHandler = &MockHTTPHandler{}
