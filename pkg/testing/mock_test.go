package testing_test

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
	. "github.com/BeamFoundry/rays/pkg/testing"
	. "github.com/BeamFoundry/rays/pkg/web"

	_ "github.com/BeamFoundry/rays-web-security/internal/autoconfig"

	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"
)

type UserDetailsServiceConfiguration struct {
	Configuration
}

func (this *UserDetailsServiceConfiguration) UserDetailsService(
	that struct {
		passwordEncoder PasswordEncoder `@:"Inject"`
	},
) UserDetailsService {
	userDetailsService := InMemoryUserDetailsManager{}.New(that.passwordEncoder)
	userDetailsService.NewUser().
		WithUsername("user").
		WithPassword("user").
		WithAuthorities([]GrantedAuthority{Authority("ROLE_USER"), Authority("ROLE_PRIVILEGED")}).Build()
	userDetailsService.NewUser().
		WithUsername("admin").
		WithPassword("admin").
		WithAuthorities([]GrantedAuthority{Authority("ROLE_USER"), Authority("ROLE_ADMIN")}).Build()
	return userDetailsService
}

var _ = Describe("Mock Security Filter ", func() {
	Describe("MockSecurityRouter", func() {
		var router *MockSecurityRouter

		BeforeEach(func() {
			router = NewMockSecurityRouter()
		})

		Context("when registering routes and middlewares", func() {
			It("should store registered middlewares and routes (GET & POST) across groups", func() {
				router.Use(func(_ SecurityHandler) error { return nil })

				api := router.Group("/api")
				api.Get("/users", func(_ SecurityHandler) error { return nil })
				api.Post("/users", func(_ SecurityHandler) error { return nil })

				Expect(*router.Middlewares).To(HaveLen(1))
				Expect(*router.Routes).To(HaveLen(2))

				Expect((*router.Routes)[0].Method).To(Equal("GET"))
				Expect((*router.Routes)[0].Path).To(Equal("/api/users"))

				Expect((*router.Routes)[1].Method).To(Equal("POST"))
				Expect((*router.Routes)[1].Path).To(Equal("/api/users"))
			})
		})

		Context("when executing a request via Execute()", func() {
			var handler *MockSecurityHandler

			BeforeEach(func() {
				u := ValErr(url.Parse("http://www.example.com/api/data"))
				handler = NewMockSecurityHandler(HttpMethods.GET, u)
			})

			It("should run middlewares and the matching route handler", func() {
				middlewareHit := false
				routeHit := false

				router.Use(func(_ SecurityHandler) error {
					middlewareHit = true
					return nil
				})

				router.Get("/api/data", func(_ SecurityHandler) error {
					routeHit = true
					return nil
				})

				err := router.Execute(handler)
				Expect(err).NotTo(HaveOccurred())
				Expect(middlewareHit).To(BeTrue())
				Expect(routeHit).To(BeTrue())
			})

			It("should halt and return an error if a middleware fails", func() {
				expectedErr := errors.New("middleware error")

				router.Use(func(_ SecurityHandler) error {
					return expectedErr
				})

				router.Get("/api/data", func(_ SecurityHandler) error {
					Fail("Route should not be reached if middleware fails")
					return nil
				})

				err := router.Execute(handler)
				Expect(err).To(MatchError(expectedErr))
			})

			It("should return an error if the route handler fails", func() {
				expectedErr := errors.New("route error")

				router.Get("/api/data", func(_ SecurityHandler) error {
					return expectedErr
				})

				err := router.Execute(handler)
				Expect(err).To(MatchError(expectedErr))
			})

			It("should return nil if no route matches", func() {
				router.Get("/api/other", func(_ SecurityHandler) error {
					Fail("Wrong route should not be hit")
					return nil
				})

				err := router.Execute(handler)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Describe("MockSecurityHandler", func() {
		var (
			req     *http.Request
			handler *MockSecurityHandler
		)

		BeforeEach(func() {
			// Setup a fake request with query params for FormValue testing
			req = httptest.NewRequest(http.MethodGet, "/secure-data?role=admin", http.NoBody)
			u, err := url.Parse("http://www.example.com/secure-data?role=admin")
			Expect(err).NotTo(HaveOccurred())
			handler = NewMockSecurityHandler(HttpMethods.GET, u)
			handler.SetHeader("Authorization", "Bearer fake-token")
		})

		Context("Request Inspection", func() {
			It("should return the correct Method, Path, and URL", func() {
				Expect(handler.Method()).To(Equal(http.MethodGet))
				Expect(handler.Path()).To(Equal("/secure-data"))
				Expect(handler.URL().Path).To(Equal("/secure-data"))
				Expect(handler.URL().RawQuery).To(Equal("role=admin"))
			})

			It("should read headers", func() {
				Expect(handler.Header("Authorization")).To(Equal("Bearer fake-token"))
				Expect(handler.Header("Missing")).To(BeEmpty())
			})

			It("should read form values (query params or form bodies)", func() {
				Expect(handler.FormValue("role")).To(Equal("admin"))
				Expect(handler.FormValue("missing")).To(BeEmpty())
			})
		})

		Context("Response Manipulation", func() {
			It("should set headers correctly", func() {
				handler.SetHeader("X-Custom-Header", "ginkgo-test")
				Expect(handler.Res.Header().Get("X-Custom-Header")).To(Equal("ginkgo-test"))
			})

			It("should write bytes to the response body", func() {
				n, err := handler.Write([]byte("hello world"))
				Expect(err).NotTo(HaveOccurred())
				Expect(n).To(Equal(11))
				Expect(handler.Res.Body.String()).To(Equal("hello world"))
			})
		})

		Context("Cookie Handling", func() {
			It("should set and get cookies", func() {
				testCookie := &http.Cookie{Name: "session_id", Value: "xyz123"}

				handler.SetCookie(testCookie)

				// Verify we can read it back
				retrieved, err := handler.Cookie("session_id")
				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved.Value).To(Equal("xyz123"))
			})

			It("should return an error when getting a missing cookie", func() {
				_, err := handler.Cookie("missing_cookie")
				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(http.ErrNoCookie))
			})
		})

		Context("Session Handling", func() {
			It("should set, get, and reset session values", func() {
				handler.SetSessionValue("userID", 123)
				Expect(handler.SessionValue("userID")).To(Equal(123))

				handler.SessionReset()
				Expect(handler.SessionValue("userID")).To(BeNil())
			})
		})

		Context("Body Binding", func() {
			It("should bind JSON body to an object", func() {
				// We need a specific request with a body for this test
				bodyBytes := []byte(`{"username": "admin", "active": true}`)
				// 1. Initialize with URL
				u := ValErr(url.Parse("https://example.com/login"))
				h := NewMockSecurityHandlerWithBody(HttpMethods.POST, u, bodyBytes)
				h.SetHeader("Content-Type", "application/json")

				type User struct {
					Username string `json:"username"`
					Active   bool   `json:"active"`
				}
				var user User

				err := h.BindBody(&user)
				Expect(err).NotTo(HaveOccurred())
				Expect(user.Username).To(Equal("admin"))
				Expect(user.Active).To(BeTrue())
			})
			It("should successfully bind x-www-form-urlencoded form data to a struct", func() {
				// 1. Initialize with URL
				u := ValErr(url.Parse("https://example.com/login"))
				h := NewMockSecurityHandler(HttpMethods.POST, u)

				// The constructor should have set this automatically
				Expect(h.Header("Content-Type")).To(Equal("application/x-www-form-urlencoded"))

				// 2. Set form values easily
				h.SetFormValue("user_email", "admin@test.com")
				h.SetFormValue("user_pass", "secret123")

				// 3. Define target struct with 'form' tags
				type Credentials struct {
					Email    string `form:"user_email"`
					Password string `form:"user_pass"`
					Ignored  string // No form tag
				}

				var creds Credentials

				// 4. Execute and Assert
				Expect(h.BindBody(creds)).To(HaveOccurred())
				err := h.BindBody(&creds)
				Expect(err).NotTo(HaveOccurred())

				Expect(creds.Email).To(Equal("admin@test.com"))
				Expect(creds.Password).To(Equal("secret123"))
				Expect(creds.Ignored).To(BeEmpty())
			})

			It("should toggle headers correctly when changing methods", func() {
				u := ValErr(url.Parse("https://example.com/api"))
				h := NewMockSecurityHandler(HttpMethods.POST, u)

				Expect(h.Header("Content-Type")).To(Equal("application/x-www-form-urlencoded"))

				// Switch to GET
				h.SetMethod(HttpMethods.GET)
				Expect(h.Method()).To(Equal(http.MethodGet))
				Expect(h.Header("Content-Type")).To(BeEmpty())
			})

			It("should return nil if request body is literally nil", func() {
				// httptest.NewRequest creates a body even if passed nil, so we force it to nil to test the guard clause
				req.Body = nil
				err := handler.BindBody(&map[string]string{})
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("Filter Chain Controls", func() {
			/*
				It("should record exceptions and write forbidden status", func() {
					fakeErr := SecurityFilterChainError{}.SetStatus(403)
					err := handler.HandleSecurityFilterChainException(fakeErr)

					Expect(err).To(Equal(fakeErr))
					Expect(handler.Exception).To(Equal(fakeErr))
					Expect(handler.Res.Code).To(Equal(http.StatusForbidden))
				})
			*/
		})
		Context("Reusing handler", func() {
			It("should be able to change the URL", func() {
				u := ValErr(url.Parse("https://example.com/login"))
				handler.SetURL(u)
				Expect(handler.URL().Path).To(Equal("/login"))
			})
		})
	})

	Describe("MockSecurityAppHandler", func() {
		BeforeEach(func() {
			AddBeamFor(&UserDetailsServiceConfiguration{})
			GetContainer().EnableScanning()
		})
		Context("FormLogin", func() {
			BeforeEach(func() {
				httpSecurity := (&HttpSecurityBuilder{}).
					AuthorizedHTTPRequests().
					Paths("/admin", "/admin/**").HasRole("ADMIN").
					And().
					AnyRequest().PermitAll().
					FormLogin().And().
					Build()
				AddBeamFor(httpSecurity)
				Expect(GetContainer().Initialize()).NotTo(HaveOccurred())
			})
			It("can be created", func() {
				chain := GetBeamDefaultInstance[SecurityFilterChain]()
				Expect(chain).NotTo(BeNil())
				app := NewMockSecurityAppHandler()
				chain.Initialize("primary", app)

				ex := Try(
					func() {
						handler := NewMockSecurityHandler(HttpMethods.POST, ValErr(url.Parse("http://www.example.com/admin")))
						RaiseErr(app.Execute(handler))
					},
					Catch(func(e SecurityFilterChainException) Error {
						ex, ok := e.(*DefaultSecurityFilterChainException)
						Expect(ok).To(BeTrue())
						Expect(ex.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))
						Expect(ex.To()).To(Equal("/login"))
						return e
					}),
				)
				Expect(ex).To(HaveOccurred())

				ex = Try(
					func() {
						handler := NewMockSecurityHandler(HttpMethods.POST, ValErr(url.Parse("http://www.example.com/login")))
						handler.SetFormValue("username", "admin")
						RaiseErr(app.Execute(handler))
					},
					Catch(func(e SecurityFilterChainException) Error {
						Expect(e.Action()).To(Equal(DefaultSecurityFilterAction{}.New().RENDER.Name()))
						return e
					}),
				)
				Expect(ex).To(HaveOccurred())

				ex = Try(
					func() {
						handler := NewMockSecurityHandler(HttpMethods.POST, ValErr(url.Parse("http://www.example.com/login")))
						handler.SetFormValue("username", "user")
						handler.SetFormValue("password", "user")
						handler.SetSessionValue("redirect", "/admin")
						Expect(app.Execute(handler)).To(HaveOccurred())
						handler.SetMethod(HttpMethods.GET)
						handler.SetURL(ValErr(url.Parse("http://www.example.com/admin")))
						RaiseErr(app.Execute(handler))
					},
					Catch(func(e SecurityFilterChainException) Error {
						ex, ok := e.(*DefaultSecurityFilterChainException)
						Expect(ok).To(BeTrue())
						Expect(ex.Action()).To(Equal(DefaultSecurityFilterAction{}.New().ERROR.Name()))
						Expect(ex.Status()).To(Equal(403))
						return e
					}),
				)
				Expect(ex).To(HaveOccurred())
			})
		})
		Context("Basic Auth", func() {
			BeforeEach(func() {
				httpSecurity := (&HttpSecurityBuilder{}).
					Match("/api/**", "/admin", "/admin/**").
					AuthorizedHTTPRequests().
					Paths("/admin", "/admin/**").HasRole("ADMIN").
					And().
					AnyRequest().PermitAll().
					Basic().
					Build()
				AddBeamFor(httpSecurity)
				Expect(GetContainer().Initialize()).NotTo(HaveOccurred())
			})
			It("can be created", func() {
				chain := GetBeamDefaultInstance[SecurityFilterChain]()
				Expect(chain).NotTo(BeNil())
				app := NewMockSecurityAppHandler()
				chain.Initialize("primary", app)

				base64encode := func(src string) string {
					return base64.StdEncoding.EncodeToString([]byte(src))
				}

				ex := Try(
					func() {
						handler := NewMockSecurityHandler(HttpMethods.GET, ValErr(url.Parse("http://www.example.com/admin")))
						handler.SetHeader("Authorization", "Auth "+base64encode("admin:admin"))
						RaiseErr(app.Execute(handler))
					},
				)
				Expect(ex).To(HaveOccurred())
			})
		})

		Context("MockSecurityAppHandler and Handler capabilities", func() {
			It("supports PostAuthorizationFilter and TLSConnectionState", func() {
				app := NewMockSecurityAppHandler()
				handler := NewMockSecurityHandler(HttpMethods.GET, ValErr(url.Parse("https://www.example.com/test")))

				// Test PostAuthorizationFilter
				app.PostAuthorizationFilter(handler)

				// Test TLSConnectionState
				Expect(handler.TLSConnectionState()).NotTo(BeNil())
			})
		})
	})
})
