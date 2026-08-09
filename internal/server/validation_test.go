package server

import (
	"strings"
	"testing"

	egressv1 "github.com/agynio/egress/.gen/go/agynio/api/egress/v1"
	"github.com/google/uuid"
)

func TestValidateMatcherRejectsReservedPatterns(t *testing.T) {
	for _, pattern := range []string{"*.agyn", "api.svc", "db.ns.svc", "api.cluster.local", "100.64.0.1", "100.64.0.0/24"} {
		t.Run(pattern, func(t *testing.T) {
			_, err := validateMatcher(&egressv1.EgressRuleMatcher{DomainPattern: pattern})
			if err == nil {
				t.Fatalf("expected %q to be rejected", pattern)
			}
		})
	}
}

func TestValidateMatcherDefaultsAndSortsPorts(t *testing.T) {
	matcher, err := validateMatcher(&egressv1.EgressRuleMatcher{DomainPattern: "API.Example.COM", Ports: []int32{443, 80, 443}, Methods: []string{"post", "GET", "post"}})
	if err != nil {
		t.Fatalf("validate matcher: %v", err)
	}
	if matcher.GetDomainPattern() != "api.example.com" {
		t.Fatalf("domain pattern = %q", matcher.GetDomainPattern())
	}
	if got := matcher.GetPorts(); len(got) != 2 || got[0] != 80 || got[1] != 443 {
		t.Fatalf("ports = %v", got)
	}
	if got := strings.Join(matcher.GetMethods(), ","); got != "GET,POST" {
		t.Fatalf("methods = %q", got)
	}

	matcher, err = validateMatcher(&egressv1.EgressRuleMatcher{DomainPattern: "api.example.com"})
	if err != nil {
		t.Fatalf("validate matcher: %v", err)
	}
	if got := matcher.GetPorts(); len(got) != 2 || got[0] != 80 || got[1] != 443 {
		t.Fatalf("default ports = %v", got)
	}
}

func TestValidateEffectHeaders(t *testing.T) {
	secretID := uuid.New()
	action := egressv1.EgressRuleAction_EGRESS_RULE_ACTION_ALLOW
	effect, secretIDs, err := validateEffect(&egressv1.EgressRuleEffect{
		Action: &action,
		Inject: []*egressv1.EgressRuleHeader{
			{Name: "Authorization", Scheme: egressv1.HeaderAuthScheme_HEADER_AUTH_SCHEME_BEARER, Credential: &egressv1.EgressRuleHeader_SecretId{SecretId: secretID.String()}},
			{Name: "X-Static", Credential: &egressv1.EgressRuleHeader_Value{Value: " token "}},
		},
	})
	if err != nil {
		t.Fatalf("validate effect: %v", err)
	}
	if len(secretIDs) != 1 || secretIDs[0] != secretID {
		t.Fatalf("secret ids = %v", secretIDs)
	}
	if effect.GetInject()[1].GetValue() != "token" {
		t.Fatalf("static header value not trimmed: %q", effect.GetInject()[1].GetValue())
	}
}

func TestValidateEffectRejectsDuplicateHeader(t *testing.T) {
	_, _, err := validateEffect(&egressv1.EgressRuleEffect{Inject: []*egressv1.EgressRuleHeader{
		{Name: "Authorization", Credential: &egressv1.EgressRuleHeader_Value{Value: "a"}},
		{Name: "authorization", Credential: &egressv1.EgressRuleHeader_Value{Value: "b"}},
	}})
	if err == nil {
		t.Fatal("expected duplicate header to fail")
	}
}

func TestValidateEffectRejectsMissingCredential(t *testing.T) {
	_, _, err := validateEffect(&egressv1.EgressRuleEffect{Inject: []*egressv1.EgressRuleHeader{{Name: "Authorization"}}})
	if err == nil {
		t.Fatal("expected missing credential to fail")
	}
}

func TestValidateRuleInputRejectsNoopEffect(t *testing.T) {
	organizationID := uuid.New().String()
	matcher := &egressv1.EgressRuleMatcher{DomainPattern: "api.example.com"}
	for _, effect := range []*egressv1.EgressRuleEffect{nil, {}, {Action: egressv1.EgressRuleAction_EGRESS_RULE_ACTION_UNSPECIFIED.Enum()}} {
		_, err := validateRuleInput(organizationID, "rule", "", matcher, effect)
		if err == nil {
			t.Fatalf("expected no-op effect %#v to fail", effect)
		}
	}
}

func TestValidateRuleInputAllowsMeaningfulEffect(t *testing.T) {
	organizationID := uuid.New().String()
	matcher := &egressv1.EgressRuleMatcher{DomainPattern: "api.example.com"}
	allow := egressv1.EgressRuleAction_EGRESS_RULE_ACTION_ALLOW
	if _, err := validateRuleInput(organizationID, "rule", "", matcher, &egressv1.EgressRuleEffect{Action: &allow}); err != nil {
		t.Fatalf("allow effect rejected: %v", err)
	}
	if _, err := validateRuleInput(organizationID, "rule", "", matcher, &egressv1.EgressRuleEffect{Inject: []*egressv1.EgressRuleHeader{{Name: "X-Token", Credential: &egressv1.EgressRuleHeader_Value{Value: "token"}}}}); err != nil {
		t.Fatalf("header injection effect rejected: %v", err)
	}
}
