package core_test

import (
	"net/http"
	"net/url"

	. "github.com/BeamFoundry/rays/pkg/lang"
	. "github.com/BeamFoundry/rays/pkg/testing"
	. "github.com/BeamFoundry/rays/pkg/web"

	_ "github.com/BeamFoundry/rays-web-security/internal/autoconfig"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SecurityFilterChainError", func() {
	u := ValErr(url.Parse("http://www.example.com/index.html"))
	handler := NewMockSecurityHandler(HttpMethods.GET, u)
	It("can be declared with ReportError", func() {
		err := DefaultSecurityFilterChainException{}.ReportError(NewError("Error", "Error"), http.StatusBadRequest)
		Expect(err).To(HaveOccurred())
		Expect(err.Action()).To(Equal(DefaultSecurityFilterAction{}.New().ERROR.Name()))
		Expect(err.Status()).To(Equal(400))
		Expect(err.ReportedError()).To(HaveOccurred())
		Expect(err.Handle(handler)).To(HaveOccurred())
	})

	It("can be declared with RedirectTo", func() {
		err := DefaultSecurityFilterChainException{}.RedirectTo("/login")
		Expect(err).To(HaveOccurred())
		Expect(err.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))
		Expect(err.To()).To(Equal("/login"))
		Expect(err.Handle(handler)).To(HaveOccurred())
	})

	It("can be declared with RedirectToWithCode", func() {
		err := DefaultSecurityFilterChainException{}.RedirectToWithCode("/login", 301)
		Expect(err).To(HaveOccurred())
		Expect(err.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))
		Expect(err.To()).To(Equal("/login"))
		Expect(err.Status()).To(Equal(301))
		Expect(err.Handle(handler)).To(HaveOccurred())
	})
	It("can be declared with RenderView", func() {
		err := DefaultSecurityFilterChainException{}.RenderView("login", map[string]any{"Errors": []string{}})
		Expect(err).To(HaveOccurred())
		Expect(err.Action()).To(Equal(DefaultSecurityFilterAction{}.New().RENDER.Name()))
		Expect(err.View()).To(Equal("login"))
		Expect(err.Data()).NotTo(BeEmpty())
		Expect(err.Handle(handler)).To(HaveOccurred())
	})
	It("can be declared with Next", func() {
		err := DefaultSecurityFilterChainException{}.Next()
		Expect(err).To(HaveOccurred())
		Expect(err.Action()).To(Equal(DefaultSecurityFilterAction{}.New().NEXT.Name()))
		Expect(err.Handle(handler)).NotTo(HaveOccurred())
	})
})
