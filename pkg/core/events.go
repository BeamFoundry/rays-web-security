package core

import (
	. "github.com/BeamFoundry/rays/pkg/core"
)

// SecurityEventFilter is a base marker type for an EventFilter around a security event.
// Used by [PreAuthenticationFilter] and [PostAuthorisationFilter].
type SecurityEventFilter interface {
	EventFilter
	_SecurityEventFilter()
}

// PreAuthenticationFilter is a type that a middleware should implements to indicates
// to the web framework implementation that it should be configured *before* the security process.
type PreAuthenticationFilter interface {
	SecurityEventFilter
	_PreAuthenticationFilter()
}

// PostAuthorisationFilter is a type that a middleware should implements to indicates
// to the web framework implementation that it should be configured *after* the security process.
type PostAuthorisationFilter interface {
	SecurityEventFilter
	_PostAuthorisationFilter()
}
