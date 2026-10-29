package core

import (
	"crypto/tls"
	"net/http"
	"net/url"
)

// SecurityContext is an object popuplated inside the [SecurityContextHolder] during the Authentication phase.
//
// It let you retrieve the current user [Authentication], or set it.
type SecurityContext interface {
	// GetAuthentication() returns the current [Authentication] associated with the current thread.
	//
	// It can be an Anonymous user, in which case [Authentication.IsAuthenticated] will return false.
	GetAuthentication() Authentication

	// SetAuthentication() will change the current authentication object.
	//
	// It's the responsibility of a [SecurityFilter] to either save the current [Authentication] in
	// either or both the session or in the [SecurityContext].
	SetAuthentication(authentication Authentication)

	// SetHTTPPolicyDebugValue() sets a string containing debug informations about the current
	// policy applied to the current thread.
	SetHTTPPolicyDebugValue(debug string)

	// GetHTTPPolicyDebugValue() let's retrieve the value set in SetHTTPPolicyDebugValue.
	GetHTTPPolicyDebugValue() string
}

// SecurityContextHolder is the interface that is used to set or retrieve the current [SecurityContext].
type SecurityContextHolder interface {
	// ClearContext() is called when initializing the current authntication process.
	ClearContext()

	// SetContext() lets erase the current [SecurityContext]
	SetContext(context SecurityContext)

	// GetContext() lets you retrieve the current [SecurityContext]
	GetContext() SecurityContext
}

// SecurityHandler represents a web framework agnostic web context.
type SecurityHandler interface {
	// Cookie() returns the named Cookie or an error if not found.
	Cookie(name string) (*http.Cookie, error)

	// SetCookie() sets a cookie
	SetCookie(cookie *http.Cookie)

	// FormValue() returns a named form submitted value
	FormValue(name string) string

	// Header() returns the named HTTP Header or blank
	Header(name string) string

	// SetHeader() set then named Header to value
	SetHeader(name, value string)

	// Method() returns the Request HTTP Method
	Method() string

	// Path() returns the Request Path
	Path() string

	// SessionReset() empty the current session
	SessionReset()

	// SessionRefresh() regenerate the session ID, keeping the data.
	// Used after a login, to protect against session fixing.
	SessionRefresh()

	// SessionValue() return a session value
	SessionValue(key string) any

	// SetSessionValue() sets a session value
	SetSessionValue(key string, obj any)

	// URL() returns the request URL
	URL() *url.URL

	// BindBody() bind the current Form submitted to an object
	BindBody(obj any) error

	// Redirect() set the Location header and redirect code
	Redirect(to string, code int) error

	// RenderView() render the view with data
	RenderView(view string, data map[string]any) error

	// Error() handles creating an HTTP error message
	//
	// Implementations may have a specific method for creating them.
	Error(code int, message string) error

	// Write() write the body
	Write(p []byte) (n int, err error)

	// Enable the next handler
	Next() error
}

// TLSConnectionHandler is an optional interface a [SecurityHandler] may implement
// to provide direct access to TLS connection state (e.g. for client certificate inspection).
type TLSConnectionHandler interface {
	// TLSConnectionState() returns the TLS connection state or nil if not using TLS.
	TLSConnectionState() *tls.ConnectionState
}

// SecurityRouter is a base interface used by [SecurityAppHandler].
type SecurityRouter interface {
	// Group() returns a new SecurityRouter for the given path
	Group(path string) SecurityRouter

	// Use() register a new handler
	Use(handler func(SecurityHandler) error)

	// Get() add a GET HTTP handler for the given path
	Get(path string, handler func(SecurityHandler) error)

	// Post() add a POST HTTP handler for the given path
	Post(path string, handler func(SecurityHandler) error)
}

// SecurityAppHandler is an interface a web framework connector should implements
// to interface with [github.com/BeamFoundry/rays-web-security].
//
// It is used to initialize the security on a request with the [SecurityFilterChain].
type SecurityAppHandler interface {
	// Implements [SecurityRouter]
	SecurityRouter

	// EnableCsrf() should implement what it is needed to enable CSRF for that
	// web framework connector. Before doing so it should check the result of the skip
	// function to know if it should not be done.
	EnableCsrf(skip func(handler SecurityHandler) bool)

	// EnableSession() should implement what is needed to enable Session handling for that
	// web framework connector. Before doing so it should check the result of the skip
	// function to know if it should not be done.
	EnableSession(skip func(handler SecurityHandler) bool)

	// HasSession() should returns if for that request, session has been enabled.
	HasSession(handler SecurityHandler) bool

	// PostAuthorizationFilter() is a callback
	PostAuthorizationFilter(handler SecurityHandler)
}

type SecurityFilterChain interface {
	Initialize(serverName string, app SecurityAppHandler)
}

// SecurityFilter is an interface describing a filter used to Authenticate a user.
//
// It is used by the [SecurityFilterChain] implementation.
//
// You can add your own [SecurityFilter] in an [HttpSecurity] object.
type SecurityFilter interface {
	// Authenticate() should authenticate an user, using Session or the AuthenticationManager.
	//
	// It should return a [SecurityFilterChainException] indicating what should be done next.
	Authenticate(handler SecurityHandler) SecurityFilterChainException

	// AuthenticationRequired() should return a [SecurityFilterChainException] to indicate what
	// the [SecurityFilterChain] should do if no authentication has been successful and
	// the user try to access a restricted path.
	AuthenticationRequired(handler SecurityHandler) SecurityFilterChainException
}

// SecurityEndpointRegistration is an optional interface a [SecurityFilter] may also implements
// to have some path related handler registered.
//
// They are mainly used to provide technical endpoints like "login" form display and "logout".
type SecurityEndpointRegistration interface {
	// RegisterSecurityEndpoint() let you add endpoints.
	RegisterSecurityEndpoint(router SecurityRouter)
}

// SessionAwareFilter is a marker interface a [SecurityFilter] should use to indicate
// it needs session handling.
//
// Depending on the configuration Session may be enabled only if some filters need it.
// See: [github.com/BeamFoundry/rays-web-security/pkg/config.]
type SessionAwareFilter interface {
	_SessionAwareFilter()
}
