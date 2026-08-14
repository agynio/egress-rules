package server

import (
	"strings"
	"testing"

	egressv1 "github.com/agynio/egress/.gen/go/agynio/api/egress/v1"
	zitimanagementv1 "github.com/agynio/egress/.gen/go/agynio/api/ziti_management/v1"
	"github.com/agynio/egress/internal/store"
	"github.com/google/uuid"
)

func TestCreateServiceRequestUsesForwardingHostConfig(t *testing.T) {
	ruleID := uuid.New()
	req := createServiceRequest(ruleID, &egressv1.EgressRuleMatcher{DomainPattern: "api.example.com", Ports: []int32{443}})
	if req.GetName() != "egress-rule-"+ruleID.String() {
		t.Fatalf("name = %q", req.GetName())
	}
	if len(req.GetRoleAttributes()) != 1 || req.GetRoleAttributes()[0] != "egress-services" {
		t.Fatalf("role attrs = %v", req.GetRoleAttributes())
	}
	host := req.GetHostV1Config()
	if host == nil {
		t.Fatal("missing host config")
	}
	if !host.GetForwardAddress() || !host.GetForwardPort() || !host.GetForwardProtocol() {
		t.Fatalf("forwarding flags not all enabled: %+v", host)
	}
	if got := host.GetAllowedAddresses(); len(got) != 1 || got[0] != allIPv4Addresses {
		t.Fatalf("allowed addresses = %v", got)
	}
	if got := host.GetAllowedPortRanges(); len(got) != 1 || got[0].GetLow() != minimumTCPPort || got[0].GetHigh() != maximumTCPPort {
		t.Fatalf("allowed port ranges = %v", got)
	}
	intercept := req.GetInterceptV1Config()
	if got := intercept.GetAddresses(); len(got) != 1 || got[0] != "api.example.com" {
		t.Fatalf("intercept addresses = %v", got)
	}
}

func TestServiceMatchesRuleUsesAvailableServiceFields(t *testing.T) {
	ruleID := uuid.New()
	rule := store.Rule{ID: ruleID, Matcher: &egressv1.EgressRuleMatcher{DomainPattern: "api.example.com", Ports: []int32{443}}}
	service := &zitimanagementv1.OpenZitiService{
		ZitiServiceId:  "service-id",
		Name:           egressServiceName(ruleID),
		RoleAttributes: []string{egressServiceRoleAttribute},
	}
	if !serviceMatchesRule(service, rule) {
		t.Fatal("expected service to match rule")
	}
	service.RoleAttributes = []string{"drift"}
	if serviceMatchesRule(service, rule) {
		t.Fatal("expected role drift to be detected")
	}
}

func TestServicePolicyMatchesAttachmentDetectsDrift(t *testing.T) {
	ruleID := uuid.New()
	agentID := uuid.New()
	serviceID := "ziti-service-id"
	rule := store.Rule{ID: ruleID, Matcher: &egressv1.EgressRuleMatcher{DomainPattern: "api.example.com"}, OpenZitiServiceID: serviceID}
	attachment := store.Attachment{RuleID: ruleID, AgentID: &agentID}
	policy := &zitimanagementv1.OpenZitiServicePolicy{
		ZitiServicePolicyId: "policy-id",
		Name:                egressDialPolicyName(ruleID, attachmentTarget{kind: targetKindAgent, id: agentID}),
		Type:                zitimanagementv1.ServicePolicyType_SERVICE_POLICY_TYPE_DIAL,
		IdentityRoles:       []string{agentRole(agentID)},
		ServiceRoles:        []string{zitiServiceIDRole(serviceID)},
	}
	if !servicePolicyMatchesAttachment(policy, attachment, rule) {
		t.Fatal("expected policy to match attachment")
	}
	policy.IdentityRoles = []string{"#agent-drift"}
	if servicePolicyMatchesAttachment(policy, attachment, rule) {
		t.Fatal("expected identity role drift to be detected")
	}
}

// A private-target rule's attachment dials the resource's service by its
// per-resource role attribute, which survives the service being recreated.
func TestPrivateAttachmentPolicySelectsTheResourceRole(t *testing.T) {
	resourceID := uuid.New()
	rule := store.Rule{ID: uuid.New(), Matcher: &egressv1.EgressRuleMatcher{PrivateResourceId: resourceID.String()}}
	if got, want := attachmentServiceRole(rule), "#private-resource-"+resourceID.String(); got != want {
		t.Fatalf("expected service role %q, got %q", want, got)
	}
}

// An egress rule attached to an environment has to grant the environment role:
// the Orchestrator stamps it on every workload identity running that
// environment, agent workloads and sandboxes alike. Granting only the agent
// role left a sandbox holding nothing the policy admitted, and its intercepted
// connection was reset.
func TestEnvironmentAttachmentGrantsTheEnvironmentRole(t *testing.T) {
	ruleID := uuid.New()
	environmentID := uuid.New()
	attachment := store.Attachment{RuleID: ruleID, EnvironmentID: &environmentID}

	target, err := targetForAttachment(attachment)
	if err != nil {
		t.Fatalf("target for attachment: %v", err)
	}
	if target.kind != targetKindEnvironment {
		t.Fatalf("expected an environment target, got %q", target.kind)
	}
	if got, want := target.identityRole(), "#environment-"+environmentID.String(); got != want {
		t.Fatalf("expected role %q, got %q", want, got)
	}
	if name := egressDialPolicyName(ruleID, target); !strings.Contains(name, "environment-"+environmentID.String()) {
		t.Fatalf("policy name does not name the environment: %s", name)
	}
}
