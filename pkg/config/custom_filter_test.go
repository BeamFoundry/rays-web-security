package config_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
	. "github.com/BeamFoundry/rays/pkg/testing"

	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

type TestFilterConfig struct {
	HeaderName string
}

type TestCustomFilter struct {
	Component
	Prototype

	config *TestFilterConfig
}

var _ SecurityFilter = &TestCustomFilter{}

var _ BeamPostConstructWithContext = &TestCustomFilter{}

func (this *TestCustomFilter) WithContext(ctx context.Context) Error {
	if ct := ctx.Value(PrototypeContextParentInstance); ct != nil {
		httpSecurity, ok := ct.(*HttpSecurity)
		if !ok {
			return NewError("IllegalArgumentException", "Only HttpSecurity may inject this type")
		}
		raw, ok := httpSecurity.SecurityFilters()["testCustomFilter"]
		if !ok {
			return NewError("IllegalArgumentException", "HttpSecurity does not configure testCustomFilter")
		}
		cfg, ok := raw.(*TestFilterConfig)
		if !ok {
			return NewError("IllegalArgumentException", "Invalid config type for testCustomFilter")
		}
		this.config = cfg
	}
	return nil
}

func (this *TestCustomFilter) Authenticate(_ SecurityHandler) SecurityFilterChainException {
	return DefaultSecurityFilterChainException{}.Next()
}

func (this *TestCustomFilter) AuthenticationRequired(_ SecurityHandler) SecurityFilterChainException {
	return DefaultSecurityFilterChainException{}.Next()
}

type AlwaysAcceptSecurityFilter struct {
	Component
	id int
}

var _ SecurityFilter = &AlwaysAcceptSecurityFilter{}

var _ BeamPostConstructWithContext = &AlwaysAcceptSecurityFilter{}

func (this *AlwaysAcceptSecurityFilter) WithContext(_ context.Context) Error {
	return nil
}

func (this *AlwaysAcceptSecurityFilter) Authenticate(_ SecurityHandler) SecurityFilterChainException {
	return DefaultSecurityFilterChainException{}.Next()
}

func (this *AlwaysAcceptSecurityFilter) AuthenticationRequired(_ SecurityHandler) SecurityFilterChainException {
	return DefaultSecurityFilterChainException{}.Next()
}

type CustomFilterHttpSecurityConfiguration struct {
	Configuration
	httpSecurity *HttpSecurityBuilder `@:"Inject"`
}

func (this *CustomFilterHttpSecurityConfiguration) HttpSecurity() *HttpSecurity {
	return this.httpSecurity.Build()
}

var _ = Describe("AddCustomSecurityFilter", func() {
	It("can populate and retrieve security filters", func() {
		cfg := &TestFilterConfig{HeaderName: "X-Custom"}
		httpSecurity := (&HttpSecurityBuilder{}).
			AddCustomSecurityFilter("testCustomFilter", cfg).
			Build()

		Expect(httpSecurity.SecurityFilters()).NotTo(BeNil())
		Expect(httpSecurity.SecurityFilters()).To(HaveKey("testCustomFilter"))
		Expect(httpSecurity.SecurityFilters()["testCustomFilter"]).To(Equal(cfg))
	})

	It("returns an empty map if no custom filters configured", func() {
		httpSecurity := (&HttpSecurityBuilder{}).Build()
		Expect(httpSecurity.SecurityFilters()).NotTo(BeNil())
		Expect(httpSecurity.SecurityFilters()).To(BeEmpty())
	})

	It("can be detected and injected via BeamPostConstructWithContext", func() {
		cfg := &TestFilterConfig{HeaderName: "X-Api-Key"}
		builder := (&HttpSecurityBuilder{}).
			AddCustomSecurityFilter("testCustomFilter", cfg)

		GetContainer().EnableScanning()
		AddBeamFor(builder)
		AddBeamFor(&CustomFilterHttpSecurityConfiguration{})
		AddBeamFor(&TestCustomFilter{})
		Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

		httpSecurity := GetBeamDefaultInstance[*HttpSecurity]()
		Expect(httpSecurity).NotTo(BeNil())
		Expect(httpSecurity.Filters()).NotTo(BeEmpty())

		var found *TestCustomFilter
		for _, f := range httpSecurity.Filters() {
			if tf, ok := f.(*TestCustomFilter); ok {
				found = tf
				break
			}
		}
		Expect(found).NotTo(BeNil())
		Expect(found.config).To(Equal(cfg))
	})

	It("is not injected if HttpSecurity does not configure it", func() {
		builder := &HttpSecurityBuilder{}

		GetContainer().EnableScanning()
		AddBeamFor(builder)
		AddBeamFor(&CustomFilterHttpSecurityConfiguration{})
		AddBeamFor(&TestCustomFilter{})
		Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

		httpSecurity := GetBeamDefaultInstance[*HttpSecurity]()
		Expect(httpSecurity).NotTo(BeNil())

		var found *TestCustomFilter
		for _, f := range httpSecurity.Filters() {
			if tf, ok := f.(*TestCustomFilter); ok {
				found = tf
				break
			}
		}
		Expect(found).To(BeNil())
	})

	It("automatically injects a filter that always accepts registration without checking SecurityFilters", func() {
		builder := &HttpSecurityBuilder{}

		GetContainer().EnableScanning()
		AddBeamFor(builder)
		AddBeamFor(&CustomFilterHttpSecurityConfiguration{})
		AddBeamFor(&AlwaysAcceptSecurityFilter{})
		Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

		httpSecurity := GetBeamDefaultInstance[*HttpSecurity]()
		Expect(httpSecurity).NotTo(BeNil())

		var found *AlwaysAcceptSecurityFilter
		for _, f := range httpSecurity.Filters() {
			if af, ok := f.(*AlwaysAcceptSecurityFilter); ok {
				found = af
				break
			}
		}
		Expect(found).NotTo(BeNil())
	})

	It("prevents duplicate filters when already added via AddCustomFilter", func() {
		filter := &AlwaysAcceptSecurityFilter{id: 1}
		builder := (&HttpSecurityBuilder{}).AddCustomFilter(filter)

		GetContainer().EnableScanning()
		AddBeamFor(filter)
		AddBeamFor(builder)
		AddBeamFor(&CustomFilterHttpSecurityConfiguration{})
		Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

		httpSecurity := GetBeamDefaultInstance[*HttpSecurity]()
		Expect(httpSecurity).NotTo(BeNil())

		count := 0
		for _, f := range httpSecurity.Filters() {
			if f == filter {
				count++
			}
		}
		Expect(count).To(Equal(1))
	})
})
