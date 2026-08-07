package server

import (
	"context"
	"testing"
	"time"

	egressv1 "github.com/agynio/egress/.gen/go/agynio/api/egress/v1"
	zitimanagementv1 "github.com/agynio/egress/.gen/go/agynio/api/ziti_management/v1"
	"github.com/agynio/egress/internal/store"
	"github.com/google/uuid"
)

func TestReconcileReplacesAttachmentPolicyUsingZitiServiceID(t *testing.T) {
	ruleID := uuid.New()
	agentID := uuid.New()
	attachmentID := uuid.New()
	rule := store.Rule{
		ID:                ruleID,
		Matcher:           &egressv1.EgressRuleMatcher{DomainPattern: "api.example.com", Ports: []int32{443}},
		Effect:            allowEffect(),
		OpenZitiServiceID: "ziti-service-id",
	}
	attachment := store.Attachment{ID: attachmentID, RuleID: ruleID, AgentID: &agentID, OpenZitiDialPolicyID: "old-policy-id", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	storeFake := &fakeRuleStore{rules: []store.Rule{rule}, attachments: []store.Attachment{attachment}}
	zitiFake := &fakeZitiManagementClient{
		ruleID:    ruleID,
		serviceID: "ziti-service-id",
		policyID:  "new-policy-id",
		servicePolicy: &zitimanagementv1.OpenZitiServicePolicy{
			ZitiServicePolicyId: "old-policy-id",
			Name:                egressDialPolicyName(ruleID, attachmentTarget{kind: targetKindAgent, id: agentID}),
			Type:                zitimanagementv1.ServicePolicyType_SERVICE_POLICY_TYPE_DIAL,
			IdentityRoles:       []string{agentRole(agentID)},
			ServiceRoles:        []string{zitiServiceIDRole("stale-ziti-service-id")},
		},
	}
	srv := New(Options{Store: storeFake, ZitiClient: zitiFake})

	if err := srv.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if zitiFake.deleteServicePolicyCalls != 1 {
		t.Fatalf("delete policy calls = %d", zitiFake.deleteServicePolicyCalls)
	}
	if zitiFake.createServicePolicyCalls != 1 {
		t.Fatalf("create policy calls = %d", zitiFake.createServicePolicyCalls)
	}
	if zitiFake.updateServiceCalls != 0 {
		t.Fatalf("update service calls = %d", zitiFake.updateServiceCalls)
	}
	if storeFake.updatedPolicyID != "new-policy-id" {
		t.Fatalf("updated policy id = %q", storeFake.updatedPolicyID)
	}
	if got := zitiFake.lastPolicy.GetServiceRoles(); len(got) != 1 || got[0] != zitiServiceIDRole("ziti-service-id") {
		t.Fatalf("service roles = %v", got)
	}
}

func TestReconcileProvisionsMissingRuleServiceBeforeAttachmentPolicy(t *testing.T) {
	ruleID := uuid.New()
	agentID := uuid.New()
	attachmentID := uuid.New()
	rule := store.Rule{ID: ruleID, Matcher: &egressv1.EgressRuleMatcher{DomainPattern: "api.example.com", Ports: []int32{443}}, Effect: allowEffect()}
	attachment := store.Attachment{ID: attachmentID, RuleID: ruleID, AgentID: &agentID, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	storeFake := &fakeRuleStore{rules: []store.Rule{rule}, attachments: []store.Attachment{attachment}}
	zitiFake := &fakeZitiManagementClient{serviceID: "created-ziti-service-id", policyID: "new-policy-id"}
	srv := New(Options{Store: storeFake, ZitiClient: zitiFake})

	if err := srv.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if zitiFake.createServiceCalls != 1 {
		t.Fatalf("create service calls = %d", zitiFake.createServiceCalls)
	}
	if storeFake.updatedServiceID != "created-ziti-service-id" {
		t.Fatalf("updated service id = %q", storeFake.updatedServiceID)
	}
	if storeFake.updatedPolicyID != "new-policy-id" {
		t.Fatalf("updated policy id = %q", storeFake.updatedPolicyID)
	}
	if got := zitiFake.lastPolicy.GetServiceRoles(); len(got) != 1 || got[0] != zitiServiceIDRole("created-ziti-service-id") {
		t.Fatalf("service roles = %v", got)
	}
}
