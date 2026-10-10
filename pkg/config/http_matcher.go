package config

import (
	"fmt"

	. "github.com/BeamFoundry/rays/pkg/lang"
	. "github.com/BeamFoundry/rays/pkg/util"
	. "github.com/BeamFoundry/rays/pkg/web"
)

// HttpMatcherEnum is an Enum type to match path request.
type HttpMatcherEnum struct {
	PATHS,
	METHOD,
	METHOD_AND_PATHS Enum[HttpMatcherEnum]
}

// HttpMatcher provides additional function around a [HttpMatcherEnum]
type HttpMatcher struct {
	paths   []*AntMatcher
	matcher Enum[HttpMatcherEnum]
	method  HttpMethod
}

// Match will return true if this HttpMatcher match the provided method and path.
func (this *HttpMatcher) Match(method, path string) bool {
	switch this.matcher {
	case Enum[HttpMatcherEnum]{}.New().METHOD:
		if method == this.method.String() {
			return true
		}
	case Enum[HttpMatcherEnum]{}.New().METHOD_AND_PATHS:
		if method != this.method.String() {
			return false
		}
	default:
	}
	for _, matcher := range this.paths {
		if matcher.Match([]byte(path)) {
			return true
		}
	}
	return false
}

// String() returns a visual representation of this HttpMatcher rule.
func (this *HttpMatcher) String() string {
	switch this.matcher {
	case Enum[HttpMatcherEnum]{}.New().METHOD:
		return fmt.Sprintf("%s[%s]", this.matcher, this.method)
	case Enum[HttpMatcherEnum]{}.New().METHOD_AND_PATHS:
		return fmt.Sprintf("%s%s", this.method, this.paths)
	default:
		return fmt.Sprintf("%s%s", this.matcher, this.paths)
	}
}
