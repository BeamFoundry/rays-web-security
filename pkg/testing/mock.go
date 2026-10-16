package testing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"

	. "github.com/BeamFoundry/rays/pkg/lang"
	. "github.com/BeamFoundry/rays/pkg/web"

	"github.com/go-playground/validator/v10"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

type Route struct {
	Handler func(SecurityHandler) error
	Method  string
	Path    string
}

type MockSecurityRouter struct {
	Middlewares *[]func(SecurityHandler) error
	Routes      *[]Route
	Prefix      string
}

func NewMockSecurityRouter() *MockSecurityRouter {
	// Initialize the underlying slices
	mws := make([]func(SecurityHandler) error, 0)
	routes := make([]Route, 0)

	return &MockSecurityRouter{
		Prefix:      "",
		Middlewares: &mws, // Store pointers to the slices
		Routes:      &routes,
	}
}

func (m *MockSecurityRouter) Group(path string) SecurityRouter {
	return &MockSecurityRouter{
		Prefix:      m.Prefix + path,
		Middlewares: m.Middlewares, // Pass the exact pointer
		Routes:      m.Routes,      // Pass the exact pointer
	}
}

func (m *MockSecurityRouter) Use(handler func(SecurityHandler) error) {
	// Dereference to append, updating the shared slice header
	*m.Middlewares = append(*m.Middlewares, handler)
}

func (m *MockSecurityRouter) Get(path string, handler func(SecurityHandler) error) {
	fullPath := m.Prefix + path
	*m.Routes = append(*m.Routes, Route{Method: "GET", Path: fullPath, Handler: handler})
}

func (m *MockSecurityRouter) Post(path string, handler func(SecurityHandler) error) {
	fullPath := m.Prefix + path
	*m.Routes = append(*m.Routes, Route{Method: "POST", Path: fullPath, Handler: handler})
}

// Execute Helper
func (m *MockSecurityRouter) Execute(handler *MockSecurityHandler) error {
	for _, mw := range *m.Middlewares {
		err := mw(handler)
		if err != nil {
			return err
		}
	}

	for _, route := range *m.Routes {
		if route.Method == handler.Method() && route.Path == handler.Path() {
			return route.Handler(handler)
		}
	}
	return nil
}

type MockSecurityAppHandler struct {
	*MockSecurityRouter
}

// PostAuthorizationFilter implements [core.SecurityAppHandler].
func (m *MockSecurityAppHandler) PostAuthorizationFilter(_ SecurityHandler) {}

var _ SecurityAppHandler = &MockSecurityAppHandler{}

// EnableCsrf implements [core.SecurityAppHandler].
func (m *MockSecurityAppHandler) EnableCsrf(skip func(handler SecurityHandler) bool) {
	m.Use(func(handler SecurityHandler) error {
		skip(handler)
		return nil
	})
}

// EnableSession implements [core.SecurityAppHandler].
//
//nolint:gosec // testing only
func (m *MockSecurityAppHandler) EnableSession(skip func(handler SecurityHandler) bool) {
	m.Use(func(handler SecurityHandler) error {
		if !skip(handler) {
			handler.SetCookie(&http.Cookie{
				Name:  "session_id",
				Value: "123456",
			})
		}
		return nil
	})
}

// HasSession implements [core.SecurityAppHandler].
func (m *MockSecurityAppHandler) HasSession(handler SecurityHandler) bool {
	if _, err := handler.Cookie("session_id"); err == nil {
		return true
	}
	return false
}

func NewMockSecurityAppHandler() *MockSecurityAppHandler {
	return &MockSecurityAppHandler{
		MockSecurityRouter: NewMockSecurityRouter(),
	}
}

type MockSecurityHandler struct {
	SessionStore map[string]any
	CookieJar    map[string]*http.Cookie
	RenderData   map[string]any
	// Exception    SecurityFilterChainException
	Req          *http.Request
	Res          *httptest.ResponseRecorder
	Validator    *validator.Validate
	RenderedView string
}

var _ SecurityHandler = &MockSecurityHandler{}

func NewMockSecurityHandler(method HttpMethod, u *url.URL) *MockSecurityHandler {
	// httptest requires a string target, so we use u.String()
	// We also inject a nil body; form values will be handled via req.Form directly in the mock
	req := httptest.NewRequestWithContext(context.Background(), method.String(), u.String(), nil)

	// Explicitly set the URL object to ensure it matches the provided parameter exactly
	req.URL = u

	handler := &MockSecurityHandler{
		Req:          req,
		Res:          httptest.NewRecorder(),
		SessionStore: make(map[string]any),
		CookieJar:    make(map[string]*http.Cookie),
		Validator:    validator.New(),
	}
	handler.SetMethod(method)
	return handler
}

func NewMockSecurityHandlerWithBody(method HttpMethod, u *url.URL, body []byte) *MockSecurityHandler {
	// httptest requires a string target, so we use u.String()
	// We also inject a nil body; form values will be handled via req.Form directly in the mock
	req := httptest.NewRequestWithContext(context.Background(), method.String(), u.String(), bytes.NewBuffer(body))

	// Explicitly set the URL object to ensure it matches the provided parameter exactly
	req.URL = u

	handler := &MockSecurityHandler{
		Req:          req,
		Res:          httptest.NewRecorder(),
		SessionStore: make(map[string]any),
		CookieJar:    make(map[string]*http.Cookie),
		Validator:    validator.New(),
	}
	handler.SetMethod(method)
	return handler
}

// SetFormValue adds or overwrites a form value in the mock request.
// This modifies the underlying req.Form map directly.
func (m *MockSecurityHandler) SetFormValue(key, value string) {
	if m.Req.Form == nil {
		m.Req.Form = make(url.Values)
	}
	m.Req.Form.Set(key, value)
}

// SetMethod changes the HTTP method and adjusts the Content-Type header accordingly.
func (m *MockSecurityHandler) SetMethod(method HttpMethod) {
	m.Req.Method = method.String()
	switch method {
	case HttpMethods.GET:
		m.Req.Header.Del("Content-Type")
	case HttpMethods.POST:
		m.Req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	default:
	}
}

func (m *MockSecurityHandler) Cookie(name string) (*http.Cookie, error) {
	if cookie, ok := m.CookieJar[name]; ok {
		return cookie, nil
	}
	return nil, http.ErrNoCookie
}

func (m *MockSecurityHandler) SetCookie(cookie *http.Cookie) {
	m.CookieJar[cookie.Name] = cookie
}

func (m *MockSecurityHandler) FormValue(name string) string {
	return m.Req.FormValue(name)
}

func (m *MockSecurityHandler) Header(name string) string {
	return m.Req.Header.Get(name)
}

func (m *MockSecurityHandler) SetHeader(name, value string) {
	m.Res.Header().Set(name, value)
	m.Req.Header.Set(name, value)
}

func (m *MockSecurityHandler) Method() string {
	return m.Req.Method
}

func (m *MockSecurityHandler) Path() string {
	return m.Req.URL.Path
}

func (m *MockSecurityHandler) SessionRefresh() {
	m.SessionStore = make(map[string]any)
}

func (m *MockSecurityHandler) SessionReset() {
	m.SessionStore = make(map[string]any)
}

func (m *MockSecurityHandler) SessionValue(key string) any {
	return m.SessionStore[key]
}

func (m *MockSecurityHandler) SetSessionValue(key string, obj any) {
	m.SessionStore[key] = obj
}

func (m *MockSecurityHandler) URL() *url.URL {
	return m.Req.URL
}

func (m *MockSecurityHandler) SetURL(u *url.URL) {
	m.Req.URL = u
}

func (m *MockSecurityHandler) BindBody(obj any) error {
	contentType := m.Req.Header.Get("Content-Type")

	// 1. JSON Binding
	if strings.HasPrefix(contentType, "application/json") {
		if m.Req.Body != nil {
			//nolint:wrapcheck // Testing
			return json.NewDecoder(m.Req.Body).Decode(obj)
		}
	}

	// 2. Form URL Encoded Binding
	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		// Ensure obj is a pointer to a struct so we can modify it
		val := reflect.ValueOf(obj)
		if val.Kind() != reflect.Pointer || val.IsNil() || val.Elem().Kind() != reflect.Struct {
			return errors.New("BindBody: expected a non-nil pointer to a struct")
		}

		// Dereference the pointer
		val = val.Elem()
		typ := val.Type()

		// Iterate through all fields of the struct
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			formTag := field.Tag.Get("form")

			// Skip if no form tag is present
			if formTag == "" {
				continue
			}

			// Get the value from the mock's request (using FormValue retrieves from req.Form)
			formVal := m.FormValue(formTag)

			fieldVal := val.Field(i)
			// Assign the value if the field is an exported string
			if fieldVal.CanSet() && fieldVal.Kind() == reflect.String {
				fieldVal.SetString(formVal)
			}
		}
		if err := m.Validator.Struct(obj); err != nil {
			return fmt.Errorf("%w", err)
		}
		return nil
	}

	// Fallback if no matching content type
	return nil
}

// Next implements [internals.SecurityHandler].
func (m *MockSecurityHandler) Next() error {
	return nil
}

/*
func (m *MockSecurityHandler) Next() error {
	m.NextCalled = true
	return nil
}
*/

func (m *MockSecurityHandler) Error(code int, message string) error {
	return DefaultSecurityFilterChainException{}.ReportError(NewError("HttpError", message), code)
}

// Redirect implements [internals.SecurityHandler].
func (m *MockSecurityHandler) Redirect(to string, code int) error {
	m.Res.WriteHeader(code)
	m.SetHeader("Location", to)
	return DefaultSecurityFilterChainException{}.RedirectToWithCode(to, code)
}

// RenderView implements [internals.SecurityHandler].
func (m *MockSecurityHandler) RenderView(view string, data map[string]any) error {
	return DefaultSecurityFilterChainException{}.RenderView(view, data)
}

func (m *MockSecurityHandler) Write(p []byte) (n int, err error) {
	//nolint:wrapcheck // Not Needed
	return m.Res.Write(p)
}
