package testing

import (
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

type MockHttpRouter struct {
	handler *MockHTTPHandler
}

func (this *MockHttpRouter) SetHandler(handler *MockHTTPHandler) {
	this.handler = handler
}

// Get implements [core.SecurityHTTPRouter].
func (this *MockHttpRouter) Get(path string, handler func(SecurityHandler) error) {
	//nolint:errcheck // Mocking
	handler(this.handler)
}

// Post implements [core.SecurityHTTPRouter].
func (this *MockHttpRouter) Post(path string, handler func(SecurityHandler) error) {
	//nolint:errcheck // Mocking
	handler(this.handler)
}

// Use implements [core.SecurityHTTPRouter].
//
//nolint:errcheck // Mocking
func (this *MockHttpRouter) Use(handler func(SecurityHandler) error) {
	handler(this.handler)
}

// BindErrorMessage implements [core.SecurityHTTPApp].
func (this *MockHttpRouter) BindErrorMessage(obj any, err error) map[string]any {
	return map[string]any{"Error": err.Error()}
}

// Group implements [core.SecurityHTTPRouter].
func (this *MockHttpRouter) Group(path string) SecurityRouter {
	return this
}

var _ SecurityRouter = &MockHttpRouter{}
