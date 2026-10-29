package config_test

import (
	"crypto/x509"
	"crypto/x509/pkix"

	. "github.com/BeamFoundry/rays-web-security/pkg/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("PreAuthConfigurer", func() {
	It("configures pre-authentication with defaults", func() {
		security := (&HttpSecurityBuilder{}).
			PreAuth().
			And().
			Build()

		Expect(security.PreAuth()).NotTo(BeNil())
		Expect(security.PreAuth().PrincipalHeader()).To(Equal("X-Remote-User"))
		Expect(security.PreAuth().CredentialsHeader()).To(BeEmpty())
		Expect(security.PreAuth().RolesHeader()).To(BeEmpty())
		Expect(security.PreAuth().RolesDelimiter()).To(Equal(","))
		Expect(security.PreAuth().AllowMtlsFallback()).To(BeTrue())
		Expect(security.PreAuth().ExceptionOnMissing()).To(BeFalse())
	})

	It("configures custom pre-authentication headers and options", func() {
		security := (&HttpSecurityBuilder{}).
			PreAuth().
			PrincipalHeader("SM_USER").
			CredentialsHeader("X-Client-Cert").
			RolesHeader("SM_GROUPS").
			RolesDelimiter(";").
			AllowMtlsFallback(false).
			ExceptionOnMissing(true).
			And().
			SessionCreationPolicy().Stateless().
			Build()

		Expect(security.PreAuth()).NotTo(BeNil())
		Expect(security.PreAuth().PrincipalHeader()).To(Equal("SM_USER"))
		Expect(security.PreAuth().CredentialsHeader()).To(Equal("X-Client-Cert"))
		Expect(security.PreAuth().RolesHeader()).To(Equal("SM_GROUPS"))
		Expect(security.PreAuth().RolesDelimiter()).To(Equal(";"))
		Expect(security.PreAuth().AllowMtlsFallback()).To(BeFalse())
		Expect(security.PreAuth().ExceptionOnMissing()).To(BeTrue())
		Expect(security.SessionCreationPolicy()).To(Equal(SessionCreationPolicy{}.New().STATELESS))
	})

	It("configures and matches trusted proxies", func() {
		security := (&HttpSecurityBuilder{}).
			PreAuth().
			TrustedProxies("proxy.internal", "CN=gateway").
			And().
			Build()

		preAuth := security.PreAuth()
		Expect(preAuth.TrustedProxies()).To(Equal([]string{"proxy.internal", "CN=gateway"}))

		// Discards empty entries
		securityWithEmpty := (&HttpSecurityBuilder{}).
			PreAuth().
			TrustedProxies("", "proxy.internal", "", "CN=gateway", "").
			And().
			Build()
		Expect(securityWithEmpty.PreAuth().TrustedProxies()).To(Equal([]string{"proxy.internal", "CN=gateway"}))

		// Matches CN
		certCN := &x509.Certificate{
			Subject: pkix.Name{CommonName: "proxy.internal"},
		}
		Expect(preAuth.IsTrustedProxy(certCN)).To(BeTrue())

		// Matches Subject.String()
		certSubj := &x509.Certificate{
			Subject: pkix.Name{CommonName: "gateway"},
		}
		Expect(preAuth.IsTrustedProxy(certSubj)).To(BeTrue())

		// Certificate with empty subject cannot be trusted
		emptyCert := &x509.Certificate{}
		Expect(preAuth.IsTrustedProxy(emptyCert)).To(BeFalse())

		// IsTrustedProxy skips empty entries even if present
		preAuth.SetTrustedProxiesForTest([]string{"", "proxy.internal"})
		Expect(preAuth.IsTrustedProxy(emptyCert)).To(BeFalse())
		Expect(preAuth.IsTrustedProxy(certCN)).To(BeTrue())

		// Non-matching cert
		untrusted := &x509.Certificate{
			Subject: pkix.Name{CommonName: "attacker.com"},
		}
		Expect(preAuth.IsTrustedProxy(untrusted)).To(BeFalse())

		// Nil cert
		Expect(preAuth.IsTrustedProxy(nil)).To(BeFalse())

		// Empty trusted proxies
		emptyPreAuth := (&HttpSecurityBuilder{}).PreAuth().And().Build().PreAuth()
		Expect(emptyPreAuth.IsTrustedProxy(certCN)).To(BeFalse())
	})
})
