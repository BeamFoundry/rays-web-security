package core

import (
	"fmt"

	. "github.com/BeamFoundry/rays/pkg/lang"
)

type AuthenticationException interface {
	Exception

	// AuthenticationRequest() returns the [Authentication] causing this Exception
	AuthenticationRequest() Authentication
}

// DefaultSecurityFilterActionEnum is an Enum type for all possible actions
type DefaultSecurityFilterActionEnum struct {
	NEXT,
	ERROR,
	REDIRECT,
	RENDER DefaultSecurityFilterAction
}

// DefaultSecurityFilterAction is an Enum alias for [DefaultSecurityFilterActionEnum]
type DefaultSecurityFilterAction = Enum[DefaultSecurityFilterActionEnum]

// SecurityFilterChainException is an interface implementing [github.com/BeamFoundry/rays/pkg/lang.Exception].
//
// It is used to designed a way to create error reported by a [SecurityFilter] and be handled by a [SecurityHandler].
type SecurityFilterChainException interface {
	// Exception is an alias for Error
	Exception

	// Action() returns thez action to execute, useful if you exception can handler multiple cases.
	Action() string

	// Handle() will process this [SecurityFilterChainException] though a [SecurityHandler] and return any error
	// that handler will return.
	//
	// it's the web framework responsibility to return error it can manage through its implementation of
	// [SecurityHandler].
	Handle(handler SecurityHandler) error
}

// DefaultSecurityFilterChainException is the default implementation of [SecurityFilterChainException].
//
// It offers constructor-like functions to directly creates all the possible [SecurityFilterChainException].
//
// TODO: Decompose it into different struct, like [AuthenticationException]
type DefaultSecurityFilterChainException struct {
	err Error
	*DefaultError
	data   map[string]any
	arg    string
	action DefaultSecurityFilterAction
	status int
}

var _ SecurityFilterChainException = &DefaultSecurityFilterChainException{}

// Action() implements [SecurityFilterChainException.Action].
func (this *DefaultSecurityFilterChainException) Action() string {
	return this.action.Name()
}

// Handle() implements [SecurityFilterChainException.Handle].
func (this *DefaultSecurityFilterChainException) Handle(handler SecurityHandler) error {
	switch this.action {
	case DefaultSecurityFilterAction{}.New().ERROR:
		return handler.Error(this.status, this.err.Message())
	case DefaultSecurityFilterAction{}.New().REDIRECT:
		return handler.Redirect(this.arg, this.status)
	case DefaultSecurityFilterAction{}.New().RENDER:
		return handler.RenderView(this.arg, this.data)
	default:
		return handler.Next()
	}
}

// ReportError() creates a new [DefaultSecurityFilterChainException] that will report an [Error] err, with the configured
// HTTP code.
//
// To create a redirect, please use [DefaultSecurityFilterChainException.RedirectTo] or [DefaultSecurityFilterChainException.RedirectToWithCode]
func (this DefaultSecurityFilterChainException) ReportError(err Error, code int) *DefaultSecurityFilterChainException {
	this.DefaultError = NewError("Error", "You should report the inner error")
	this.action = DefaultSecurityFilterAction{}.New().ERROR
	this.status = code
	this.err = err
	return &this
}

// RedirectTo() creates a new [DefaultSecurityFilterChainException] for redirecting a request to the provided url.
//
// It uses a 302 HTTP code (temporary redirect) by default.
func (this DefaultSecurityFilterChainException) RedirectTo(url string) *DefaultSecurityFilterChainException {
	return this.RedirectToWithCode(url, 302)
}

// RedirectToWithCode() creates a new [DefaultSecurityFilterChainException] for redirecting a request to the provided url
// using the provided code.
func (this DefaultSecurityFilterChainException) RedirectToWithCode(url string, code int) *DefaultSecurityFilterChainException {
	this.DefaultError = NewError("Redirect", fmt.Sprintf("You should send a redirect to '%s' with a %d HTTP status", url, code))
	this.action = DefaultSecurityFilterAction{}.New().REDIRECT
	this.arg = url
	this.status = code
	return &this
}

// RenderView() creates a new [DefaultSecurityFilterChainException] for rendering a view, with the provided data map.
func (this DefaultSecurityFilterChainException) RenderView(view string, data map[string]any) *DefaultSecurityFilterChainException {
	this.DefaultError = NewError("RenderView", fmt.Sprintf("You should render the view '%s'", view))
	this.action = DefaultSecurityFilterAction{}.New().RENDER
	this.arg = view
	this.data = data
	return &this
}

// Next() creates a new [DefaultSecurityFilterChainException] used to tell you framework to process with the next middleware.
func (this DefaultSecurityFilterChainException) Next() *DefaultSecurityFilterChainException {
	this.DefaultError = NewError("Next", "You should process with the next filter")
	this.action = DefaultSecurityFilterAction{}.New().NEXT
	return &this
}

// ReportedError() returns the configured [Error].
//
// NOTE: Provided for debugging and testing purpose.
func (this *DefaultSecurityFilterChainException) ReportedError() Error {
	return this.err
}

// Status() returns the status code used for redirect or error reporting.
//
// NOTE: Provided for debugging and testing purpose.
func (this *DefaultSecurityFilterChainException) Status() int {
	return this.status
}

// To() returns the configured url used for redirect.
//
// NOTE: Provided for debugging and testing purpose.
func (this *DefaultSecurityFilterChainException) To() string {
	return this.arg
}

// View() returns the view name configured for rendering a view.
//
// NOTE: Provided for debugging and testing purpose.
func (this *DefaultSecurityFilterChainException) View() string {
	return this.arg
}

// Data() returns the data map configured for rendering a view.
//
// NOTE: Provided for debugging and testing purpose.
func (this *DefaultSecurityFilterChainException) Data() map[string]any {
	return this.data
}
