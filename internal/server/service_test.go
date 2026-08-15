package server

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	authorizationv1 "github.com/agynio/egress/.gen/go/agynio/api/authorization/v1"
	egressv1 "github.com/agynio/egress/.gen/go/agynio/api/egress/v1"
	notificationsv1 "github.com/agynio/egress/.gen/go/agynio/api/notifications/v1"
	secretsv1 "github.com/agynio/egress/.gen/go/agynio/api/secrets/v1"
	zitimanagementv1 "github.com/agynio/egress/.gen/go/agynio/api/ziti_management/v1"
	"github.com/agynio/egress/internal/store"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestCreateEgressRuleAttachmentRequiresAgentOrg(t *testing.T) {
	callerID := uuid.New()
	ruleID := uuid.New()
	agentID := uuid.New()
	organizationID := uuid.New()

	storeFake := &fakeRuleStore{rule: store.Rule{ID: ruleID, OrganizationID: organizationID, Matcher: &egressv1.EgressRuleMatcher{DomainPattern: "api.example.com"}, Effect: &egressv1.EgressRuleEffect{}}}
	authzFake := &fakeAuthorizationClient{allowed: map[string]bool{
		tupleKey(identityObject(callerID), organizationMemberRelation, organizationObject(organizationID)): true,
		tupleKey(identityObject(callerID), agentCanEditConfigRelation, agentObject(agentID)):               true,
		tupleKey(organizationObject(organizationID), agentOrgRelation, agentObject(agentID)):               false,
	}}
	zitiFake := &fakeZitiManagementClient{}

	srv := New(Options{Store: storeFake, AuthorizationClient: authzFake, NotificationsClient: fakeNotificationsClient{}, ZitiClient: zitiFake})
	_, err := srv.CreateEgressRuleAttachment(incomingIdentityContext(callerID), &egressv1.CreateEgressRuleAttachmentRequest{RuleId: ruleID.String(), AgentId: agentID.String()})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status = %v, err = %v", status.Code(err), err)
	}
	if zitiFake.createServicePolicyCalls != 0 {
		t.Fatalf("expected no Ziti provisioning before agent org check, got %d calls", zitiFake.createServicePolicyCalls)
	}
	if storeFake.createdAttachment != nil {
		t.Fatal("expected no attachment insert before agent org check")
	}
	if !authzFake.checked(tupleKey(organizationObject(organizationID), agentOrgRelation, agentObject(agentID))) {
		t.Fatal("expected org relation check for agent membership")
	}
}

func TestCreateEgressRuleAttachmentProvisionsAfterAgentOrgAllowed(t *testing.T) {
	callerID := uuid.New()
	ruleID := uuid.New()
	agentID := uuid.New()
	organizationID := uuid.New()

	storeFake := &fakeRuleStore{rule: store.Rule{ID: ruleID, OrganizationID: organizationID, Matcher: &egressv1.EgressRuleMatcher{DomainPattern: "api.example.com"}, Effect: &egressv1.EgressRuleEffect{}, OpenZitiServiceID: "ziti-service-id", CreatedAt: time.Now(), UpdatedAt: time.Now()}}
	authzFake := &fakeAuthorizationClient{allowed: map[string]bool{
		tupleKey(identityObject(callerID), organizationMemberRelation, organizationObject(organizationID)): true,
		tupleKey(identityObject(callerID), agentCanEditConfigRelation, agentObject(agentID)):               true,
		tupleKey(organizationObject(organizationID), agentOrgRelation, agentObject(agentID)):               true,
	}}
	zitiFake := &fakeZitiManagementClient{ruleID: ruleID, serviceID: "ziti-service-id", policyID: "policy-id"}

	srv := New(Options{Store: storeFake, AuthorizationClient: authzFake, NotificationsClient: fakeNotificationsClient{}, ZitiClient: zitiFake})
	resp, err := srv.CreateEgressRuleAttachment(incomingIdentityContext(callerID), &egressv1.CreateEgressRuleAttachmentRequest{RuleId: ruleID.String(), AgentId: agentID.String()})
	if err != nil {
		t.Fatalf("CreateEgressRuleAttachment: %v", err)
	}
	if resp.GetEgressRuleAttachment().GetRuleId() != ruleID.String() {
		t.Fatalf("rule id = %q", resp.GetEgressRuleAttachment().GetRuleId())
	}
	if zitiFake.createServicePolicyCalls != 1 {
		t.Fatalf("ziti policy calls = %d", zitiFake.createServicePolicyCalls)
	}
	if zitiFake.updateServiceCalls != 0 {
		t.Fatalf("update service calls = %d", zitiFake.updateServiceCalls)
	}
	if got := zitiFake.lastPolicy.GetServiceRoles(); len(got) != 1 || got[0] != zitiServiceIDRole("ziti-service-id") {
		t.Fatalf("service roles = %v", got)
	}
}

func TestCreateEgressRuleAttachmentReconcilesStaleRuleService(t *testing.T) {
	callerID := uuid.New()
	ruleID := uuid.New()
	agentID := uuid.New()
	organizationID := uuid.New()

	storeFake := &fakeRuleStore{rule: store.Rule{ID: ruleID, OrganizationID: organizationID, Matcher: &egressv1.EgressRuleMatcher{DomainPattern: "api.example.com"}, Effect: allowEffect(), OpenZitiServiceID: "stale-ziti-service-id", CreatedAt: time.Now(), UpdatedAt: time.Now()}}
	authzFake := &fakeAuthorizationClient{allowed: map[string]bool{
		tupleKey(identityObject(callerID), organizationMemberRelation, organizationObject(organizationID)): true,
		tupleKey(identityObject(callerID), agentCanEditConfigRelation, agentObject(agentID)):               true,
		tupleKey(organizationObject(organizationID), agentOrgRelation, agentObject(agentID)):               true,
	}}
	zitiFake := &fakeZitiManagementClient{serviceID: "recreated-ziti-service-id", policyID: "policy-id", getServiceErr: status.Error(codes.NotFound, "service missing")}

	srv := New(Options{Store: storeFake, AuthorizationClient: authzFake, NotificationsClient: fakeNotificationsClient{}, ZitiClient: zitiFake})
	_, err := srv.CreateEgressRuleAttachment(incomingIdentityContext(callerID), &egressv1.CreateEgressRuleAttachmentRequest{RuleId: ruleID.String(), AgentId: agentID.String()})
	if err != nil {
		t.Fatalf("CreateEgressRuleAttachment: %v", err)
	}
	if zitiFake.getServiceCalls != 1 {
		t.Fatalf("get service calls = %d", zitiFake.getServiceCalls)
	}
	if zitiFake.createServiceCalls != 1 {
		t.Fatalf("create service calls = %d", zitiFake.createServiceCalls)
	}
	if storeFake.updatedServiceID != "recreated-ziti-service-id" {
		t.Fatalf("updated service id = %q", storeFake.updatedServiceID)
	}
	if got := zitiFake.lastPolicy.GetServiceRoles(); len(got) != 1 || got[0] != zitiServiceIDRole("recreated-ziti-service-id") {
		t.Fatalf("service roles = %v", got)
	}
}

func TestCreateEgressRuleAttachmentProvisionsMissingRuleServiceFirst(t *testing.T) {
	callerID := uuid.New()
	ruleID := uuid.New()
	agentID := uuid.New()
	organizationID := uuid.New()

	storeFake := &fakeRuleStore{rule: store.Rule{ID: ruleID, OrganizationID: organizationID, Matcher: &egressv1.EgressRuleMatcher{DomainPattern: "api.example.com"}, Effect: allowEffect(), CreatedAt: time.Now(), UpdatedAt: time.Now()}}
	authzFake := &fakeAuthorizationClient{allowed: map[string]bool{
		tupleKey(identityObject(callerID), organizationMemberRelation, organizationObject(organizationID)): true,
		tupleKey(identityObject(callerID), agentCanEditConfigRelation, agentObject(agentID)):               true,
		tupleKey(organizationObject(organizationID), agentOrgRelation, agentObject(agentID)):               true,
	}}
	zitiFake := &fakeZitiManagementClient{serviceID: "created-ziti-service-id", policyID: "policy-id"}

	srv := New(Options{Store: storeFake, AuthorizationClient: authzFake, NotificationsClient: fakeNotificationsClient{}, ZitiClient: zitiFake})
	_, err := srv.CreateEgressRuleAttachment(incomingIdentityContext(callerID), &egressv1.CreateEgressRuleAttachmentRequest{RuleId: ruleID.String(), AgentId: agentID.String()})
	if err != nil {
		t.Fatalf("CreateEgressRuleAttachment: %v", err)
	}
	if zitiFake.createServiceCalls != 1 {
		t.Fatalf("create service calls = %d", zitiFake.createServiceCalls)
	}
	if storeFake.updatedServiceID != "created-ziti-service-id" {
		t.Fatalf("updated service id = %q", storeFake.updatedServiceID)
	}
	if got := zitiFake.lastPolicy.GetServiceRoles(); len(got) != 1 || got[0] != zitiServiceIDRole("created-ziti-service-id") {
		t.Fatalf("service roles = %v", got)
	}
}

func TestUpdateEgressRuleDoesNotPersistWhenZitiUpdateFails(t *testing.T) {
	callerID := uuid.New()
	ruleID := uuid.New()
	organizationID := uuid.New()
	existingMatcher := &egressv1.EgressRuleMatcher{DomainPattern: "api.example.com", Ports: []int32{443}}

	storeFake := &fakeRuleStore{
		rule: store.Rule{
			ID:                ruleID,
			OrganizationID:    organizationID,
			Name:              "api",
			Matcher:           existingMatcher,
			Effect:            allowEffect(),
			OpenZitiServiceID: "service-id",
		},
	}
	authzFake := &fakeAuthorizationClient{allowed: map[string]bool{
		tupleKey(identityObject(callerID), organizationOwnerRelation, organizationObject(organizationID)): true,
	}}
	zitiFake := &fakeZitiManagementClient{updateServiceErr: errors.New("ziti unavailable")}

	srv := New(Options{Store: storeFake, AuthorizationClient: authzFake, SecretsClient: fakeSecretsClient{}, NotificationsClient: fakeNotificationsClient{}, ZitiClient: zitiFake})
	_, err := srv.UpdateEgressRule(incomingIdentityContext(callerID), &egressv1.UpdateEgressRuleRequest{
		Id:      ruleID.String(),
		Matcher: &egressv1.EgressRuleMatcher{DomainPattern: "api2.example.com", Ports: []int32{443}},
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("status = %v, err = %v", status.Code(err), err)
	}
	if zitiFake.updateServiceCalls != 1 {
		t.Fatalf("update service calls = %d", zitiFake.updateServiceCalls)
	}
	if storeFake.rule.Matcher.GetDomainPattern() != "api.example.com" {
		t.Fatalf("rule matcher persisted after ziti failure: %s", storeFake.rule.Matcher.GetDomainPattern())
	}
}

func TestUpdateEgressRuleUpdatesZitiWhenMatcherInterceptChanges(t *testing.T) {
	callerID := uuid.New()
	ruleID := uuid.New()
	organizationID := uuid.New()

	storeFake := &fakeRuleStore{rule: store.Rule{
		ID:                ruleID,
		OrganizationID:    organizationID,
		Name:              "api rule",
		Matcher:           &egressv1.EgressRuleMatcher{DomainPattern: "api.example.com", Ports: []int32{443}},
		Effect:            allowEffect(),
		OpenZitiServiceID: "service-id",
	}}
	authzFake := &fakeAuthorizationClient{allowed: map[string]bool{
		tupleKey(identityObject(callerID), organizationOwnerRelation, organizationObject(organizationID)): true,
	}}
	zitiFake := &fakeZitiManagementClient{serviceID: "updated-service-id"}

	srv := New(Options{Store: storeFake, AuthorizationClient: authzFake, SecretsClient: fakeSecretsClient{}, NotificationsClient: fakeNotificationsClient{}, ZitiClient: zitiFake})
	_, err := srv.UpdateEgressRule(incomingIdentityContext(callerID), &egressv1.UpdateEgressRuleRequest{
		Id:      ruleID.String(),
		Matcher: &egressv1.EgressRuleMatcher{DomainPattern: "api2.example.com", Ports: []int32{80}},
	})
	if err != nil {
		t.Fatalf("UpdateEgressRule: %v", err)
	}
	if zitiFake.updateServiceCalls != 1 {
		t.Fatalf("update service calls = %d", zitiFake.updateServiceCalls)
	}
	if storeFake.rule.OpenZitiServiceID != "updated-service-id" {
		t.Fatalf("rule service id = %q", storeFake.rule.OpenZitiServiceID)
	}
	if zitiFake.lastUpdate.GetZitiServiceId() != "service-id" {
		t.Fatalf("update ziti service id = %q", zitiFake.lastUpdate.GetZitiServiceId())
	}
	host := zitiFake.lastUpdate.GetHostV1Config()
	if host == nil || !host.GetForwardAddress() || !host.GetForwardPort() || !host.GetForwardProtocol() {
		t.Fatalf("host config = %+v", host)
	}
	intercept := zitiFake.lastUpdate.GetInterceptV1Config()
	if got := intercept.GetAddresses(); len(got) != 1 || got[0] != "api2.example.com" {
		t.Fatalf("intercept addresses = %v", got)
	}
	if got := intercept.GetPortRanges(); len(got) != 1 || got[0].GetLow() != 80 || got[0].GetHigh() != 80 {
		t.Fatalf("intercept ports = %v", got)
	}
}

func TestUpdateEgressRuleSkipsZitiWhenMatcherInterceptUnchanged(t *testing.T) {
	callerID := uuid.New()
	ruleID := uuid.New()
	organizationID := uuid.New()

	storeFake := &fakeRuleStore{rule: store.Rule{
		ID:                ruleID,
		OrganizationID:    organizationID,
		Name:              "api rule",
		Matcher:           &egressv1.EgressRuleMatcher{DomainPattern: "api.example.com", Ports: []int32{443}, Methods: []string{"GET"}},
		Effect:            allowEffect(),
		OpenZitiServiceID: "service-id",
	}}
	authzFake := &fakeAuthorizationClient{allowed: map[string]bool{
		tupleKey(identityObject(callerID), organizationOwnerRelation, organizationObject(organizationID)): true,
	}}
	zitiFake := &fakeZitiManagementClient{}

	srv := New(Options{Store: storeFake, AuthorizationClient: authzFake, SecretsClient: fakeSecretsClient{}, NotificationsClient: fakeNotificationsClient{}, ZitiClient: zitiFake})
	_, err := srv.UpdateEgressRule(incomingIdentityContext(callerID), &egressv1.UpdateEgressRuleRequest{
		Id:      ruleID.String(),
		Matcher: &egressv1.EgressRuleMatcher{DomainPattern: "api.example.com", Ports: []int32{443}, Methods: []string{"POST"}},
	})
	if err != nil {
		t.Fatalf("UpdateEgressRule: %v", err)
	}
	if zitiFake.updateServiceCalls != 0 {
		t.Fatalf("update service calls = %d", zitiFake.updateServiceCalls)
	}
}

func TestDuplicateAttachmentReturnsAlreadyExistsWithoutPolicyCleanup(t *testing.T) {
	callerID := uuid.New()
	ruleID := uuid.New()
	agentID := uuid.New()
	attachmentID := uuid.New()
	organizationID := uuid.New()
	existing := store.Attachment{ID: attachmentID, RuleID: ruleID, AgentID: &agentID, OpenZitiDialPolicyID: "existing-policy", CreatedAt: time.Now(), UpdatedAt: time.Now()}

	storeFake := &fakeRuleStore{
		rule:           store.Rule{ID: ruleID, OrganizationID: organizationID, Matcher: &egressv1.EgressRuleMatcher{DomainPattern: "api.example.com"}, Effect: allowEffect()},
		existingByPair: &existing,
	}
	authzFake := &fakeAuthorizationClient{allowed: map[string]bool{
		tupleKey(identityObject(callerID), organizationMemberRelation, organizationObject(organizationID)): true,
		tupleKey(identityObject(callerID), agentCanEditConfigRelation, agentObject(agentID)):               true,
		tupleKey(organizationObject(organizationID), agentOrgRelation, agentObject(agentID)):               true,
	}}
	zitiFake := &fakeZitiManagementClient{policyID: "existing-policy"}

	srv := New(Options{Store: storeFake, AuthorizationClient: authzFake, NotificationsClient: fakeNotificationsClient{}, ZitiClient: zitiFake})
	_, err := srv.CreateEgressRuleAttachment(incomingIdentityContext(callerID), &egressv1.CreateEgressRuleAttachmentRequest{RuleId: ruleID.String(), AgentId: agentID.String()})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("status = %v, err = %v", status.Code(err), err)
	}
	if zitiFake.createServicePolicyCalls != 0 || zitiFake.deleteServicePolicyCalls != 0 {
		t.Fatalf("expected no Ziti create/delete for duplicate, got create=%d delete=%d", zitiFake.createServicePolicyCalls, zitiFake.deleteServicePolicyCalls)
	}
	if storeFake.createdAttachment != nil {
		t.Fatal("expected no attachment insert for duplicate")
	}
}

func TestListEgressRuleAttachmentsByAgentRequiresAgentRead(t *testing.T) {
	callerID := uuid.New()
	agentID := uuid.New()
	organizationID := uuid.New()

	storeFake := &fakeRuleStore{}
	authzFake := &fakeAuthorizationClient{allowed: map[string]bool{
		tupleKey(identityObject(callerID), organizationMemberRelation, organizationObject(organizationID)): true,
	}}
	srv := New(Options{Store: storeFake, AuthorizationClient: authzFake, NotificationsClient: fakeNotificationsClient{}, ZitiClient: &fakeZitiManagementClient{}})

	_, err := srv.ListEgressRuleAttachments(incomingIdentityContext(callerID), &egressv1.ListEgressRuleAttachmentsRequest{OrganizationId: organizationID.String(), AgentId: stringPtr(agentID.String())})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status = %v, err = %v", status.Code(err), err)
	}
	if !authzFake.checked(tupleKey(identityObject(callerID), agentCanReadConfigRelation, agentObject(agentID))) {
		t.Fatal("expected can_read_config check on agent")
	}
	if authzFake.checked(tupleKey(identityObject(callerID), organizationMemberRelation, organizationObject(organizationID))) {
		t.Fatal("expected agent-scoped listing not to use org membership only")
	}
	if storeFake.listAttachmentsCalls != 0 {
		t.Fatalf("list attachments calls = %d", storeFake.listAttachmentsCalls)
	}
}

func TestListEgressRuleAttachmentsByRuleVerifiesRuleOrganization(t *testing.T) {
	callerID := uuid.New()
	ruleID := uuid.New()
	requestedOrganizationID := uuid.New()
	ruleOrganizationID := uuid.New()

	storeFake := &fakeRuleStore{rule: store.Rule{ID: ruleID, OrganizationID: ruleOrganizationID, Matcher: &egressv1.EgressRuleMatcher{DomainPattern: "api.example.com"}, Effect: allowEffect()}}
	authzFake := &fakeAuthorizationClient{allowed: map[string]bool{
		tupleKey(identityObject(callerID), organizationMemberRelation, organizationObject(ruleOrganizationID)): true,
	}}
	srv := New(Options{Store: storeFake, AuthorizationClient: authzFake, NotificationsClient: fakeNotificationsClient{}, ZitiClient: &fakeZitiManagementClient{}})

	_, err := srv.ListEgressRuleAttachments(incomingIdentityContext(callerID), &egressv1.ListEgressRuleAttachmentsRequest{OrganizationId: requestedOrganizationID.String(), RuleId: stringPtr(ruleID.String())})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("status = %v, err = %v", status.Code(err), err)
	}
	if authzFake.checked(tupleKey(identityObject(callerID), organizationMemberRelation, organizationObject(ruleOrganizationID))) {
		t.Fatal("expected no membership check when rule is outside requested org")
	}
	if storeFake.listAttachmentsCalls != 0 {
		t.Fatalf("list attachments calls = %d", storeFake.listAttachmentsCalls)
	}
}

func incomingIdentityContext(identityID uuid.UUID) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(identityMetadata, identityID.String()))
}

func tupleKey(user string, relation string, object string) string {
	return fmt.Sprintf("%s|%s|%s", user, relation, object)
}

func stringPtr(value string) *string {
	return &value
}

func allowEffect() *egressv1.EgressRuleEffect {
	return &egressv1.EgressRuleEffect{Action: egressv1.EgressRuleAction_EGRESS_RULE_ACTION_ALLOW.Enum()}
}

type fakeAuthorizationClient struct {
	allowed map[string]bool
	checks  []string
}

func (f *fakeAuthorizationClient) Check(_ context.Context, req *authorizationv1.CheckRequest, _ ...grpc.CallOption) (*authorizationv1.CheckResponse, error) {
	key := req.GetTupleKey()
	value := tupleKey(key.GetUser(), key.GetRelation(), key.GetObject())
	f.checks = append(f.checks, value)
	return &authorizationv1.CheckResponse{Allowed: f.allowed[value]}, nil
}

func (f *fakeAuthorizationClient) checked(expected string) bool {
	for _, check := range f.checks {
		if check == expected {
			return true
		}
	}
	return false
}

type fakeRuleStore struct {
	rulesByEnvironment   []store.Rule
	rulesByAgent         []store.Rule
	rule                 store.Rule
	created              *store.Rule
	rules                []store.Rule
	attachments          []store.Attachment
	existingByPair       *store.Attachment
	updateRuleErr        error
	updatedServiceID     string
	updatedPolicyID      string
	createdAttachment    *store.Attachment
	listAttachmentsCalls int
}

func (f *fakeRuleStore) CreateRule(_ context.Context, rule store.Rule) error {
	f.created = &rule
	f.rule = rule
	f.rules = append(f.rules, rule)
	return nil
}
func (f *fakeRuleStore) UpdateRule(_ context.Context, rule store.Rule) error {
	if f.updateRuleErr != nil {
		return f.updateRuleErr
	}
	f.rule = rule
	return nil
}
func (f *fakeRuleStore) UpdateRuleServiceID(_ context.Context, _ uuid.UUID, serviceID string) error {
	f.updatedServiceID = serviceID
	return nil
}
func (f *fakeRuleStore) GetRule(context.Context, uuid.UUID) (store.Rule, error) { return f.rule, nil }
func (f *fakeRuleStore) ListRules(context.Context, uuid.UUID, store.RuleListFilter, int32, *store.PageCursor) (store.RuleListResult, error) {
	return store.RuleListResult{}, nil
}
func (f *fakeRuleStore) ListAllRules(context.Context) ([]store.Rule, error) {
	return f.rules, nil
}
func (f *fakeRuleStore) ListRulesByAgent(context.Context, uuid.UUID) ([]store.Rule, error) {
	return f.rulesByAgent, nil
}
func (f *fakeRuleStore) ListRulesByEnvironment(context.Context, uuid.UUID) ([]store.Rule, error) {
	return f.rulesByEnvironment, nil
}
func (f *fakeRuleStore) DeleteRule(context.Context, uuid.UUID) error { return nil }
func (f *fakeRuleStore) CountAttachmentsByRule(context.Context, uuid.UUID) (int32, error) {
	return 0, nil
}
func (f *fakeRuleStore) CreateAttachment(_ context.Context, attachment store.Attachment) error {
	f.createdAttachment = &attachment
	return nil
}
func (f *fakeRuleStore) UpdateAttachmentPolicyID(_ context.Context, _ uuid.UUID, policyID string) error {
	f.updatedPolicyID = policyID
	return nil
}
func (f *fakeRuleStore) GetAttachment(context.Context, uuid.UUID) (store.Attachment, error) {
	if f.createdAttachment == nil {
		return store.Attachment{}, store.ErrAttachmentNotFound
	}
	attachment := *f.createdAttachment
	attachment.CreatedAt = time.Now()
	attachment.UpdatedAt = attachment.CreatedAt
	return attachment, nil
}
func (f *fakeRuleStore) GetAttachmentByRuleAndAgent(context.Context, uuid.UUID, uuid.UUID) (store.Attachment, error) {
	if f.existingByPair == nil {
		return store.Attachment{}, store.ErrAttachmentNotFound
	}
	return *f.existingByPair, nil
}
func (f *fakeRuleStore) GetAttachmentByRuleAndTarget(context.Context, uuid.UUID, string, uuid.UUID) (store.Attachment, error) {
	if f.existingByPair == nil {
		return store.Attachment{}, store.ErrAttachmentNotFound
	}
	return *f.existingByPair, nil
}
func (f *fakeRuleStore) ListAllAttachments(context.Context) ([]store.Attachment, error) {
	return f.attachments, nil
}
func (f *fakeRuleStore) ListAttachments(context.Context, uuid.UUID, *uuid.UUID, *uuid.UUID, int32, *store.PageCursor) (store.AttachmentListResult, error) {
	f.listAttachmentsCalls++
	return store.AttachmentListResult{}, nil
}
func (f *fakeRuleStore) DeleteAttachment(context.Context, uuid.UUID) error { return nil }
func (f *fakeRuleStore) CountRulesReferencingSecret(context.Context, uuid.UUID) (int32, []uuid.UUID, error) {
	return 0, nil, nil
}

func (f *fakeRuleStore) CountRulesReferencingPrivateResource(_ context.Context, resourceID uuid.UUID) (int32, []uuid.UUID, error) {
	ids := []uuid.UUID{}
	for _, rule := range f.rules {
		if rule.Matcher.GetPrivateResourceId() == resourceID.String() {
			ids = append(ids, rule.ID)
		}
	}
	return int32(len(ids)), ids, nil
}

func (f *fakeRuleStore) ListMediatedPrivateResourceIDs(context.Context, uuid.UUID) ([]uuid.UUID, error) {
	seen := map[string]bool{}
	ids := []uuid.UUID{}
	for _, rule := range f.rules {
		raw := rule.Matcher.GetPrivateResourceId()
		if raw == "" || seen[raw] {
			continue
		}
		seen[raw] = true
		if id, err := uuid.Parse(raw); err == nil {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

type fakeZitiManagementClient struct {
	ruleID                   uuid.UUID
	serviceID                string
	policyID                 string
	createServiceCalls       int
	getServiceCalls          int
	updateServiceCalls       int
	createServicePolicyCalls int
	deleteServicePolicyCalls int
	lastUpdate               *zitimanagementv1.UpdateServiceRequest
	lastPolicy               *zitimanagementv1.CreateServicePolicyRequest
	updateServiceErr         error
	getServiceErr            error
	servicePolicy            *zitimanagementv1.OpenZitiServicePolicy
}

func (f *fakeZitiManagementClient) CreateService(context.Context, *zitimanagementv1.CreateServiceRequest, ...grpc.CallOption) (*zitimanagementv1.CreateServiceResponse, error) {
	f.createServiceCalls++
	serviceID := f.serviceID
	if serviceID == "" {
		serviceID = "service-id"
	}
	return &zitimanagementv1.CreateServiceResponse{ZitiServiceId: serviceID}, nil
}
func (f *fakeZitiManagementClient) GetService(context.Context, *zitimanagementv1.GetServiceRequest, ...grpc.CallOption) (*zitimanagementv1.GetServiceResponse, error) {
	f.getServiceCalls++
	if f.getServiceErr != nil {
		return nil, f.getServiceErr
	}
	serviceID := f.serviceID
	if serviceID == "" {
		serviceID = "service-id"
	}
	return &zitimanagementv1.GetServiceResponse{Service: &zitimanagementv1.OpenZitiService{
		ZitiServiceId:  serviceID,
		Name:           egressServiceName(f.ruleID),
		RoleAttributes: []string{egressServiceRoleAttribute},
	}}, nil
}
func (f *fakeZitiManagementClient) ListServices(context.Context, *zitimanagementv1.ListServicesRequest, ...grpc.CallOption) (*zitimanagementv1.ListServicesResponse, error) {
	return &zitimanagementv1.ListServicesResponse{}, nil
}
func (f *fakeZitiManagementClient) UpdateService(_ context.Context, req *zitimanagementv1.UpdateServiceRequest, _ ...grpc.CallOption) (*zitimanagementv1.UpdateServiceResponse, error) {
	f.updateServiceCalls++
	f.lastUpdate = req
	if f.updateServiceErr != nil {
		return nil, f.updateServiceErr
	}
	serviceID := f.serviceID
	if serviceID == "" {
		serviceID = "service-id"
	}
	return &zitimanagementv1.UpdateServiceResponse{Service: &zitimanagementv1.OpenZitiService{ZitiServiceId: serviceID}}, nil
}
func (f *fakeZitiManagementClient) DeleteService(context.Context, *zitimanagementv1.DeleteServiceRequest, ...grpc.CallOption) (*zitimanagementv1.DeleteServiceResponse, error) {
	return &zitimanagementv1.DeleteServiceResponse{}, nil
}
func (f *fakeZitiManagementClient) CreateServicePolicy(_ context.Context, req *zitimanagementv1.CreateServicePolicyRequest, _ ...grpc.CallOption) (*zitimanagementv1.CreateServicePolicyResponse, error) {
	f.createServicePolicyCalls++
	f.lastPolicy = req
	return &zitimanagementv1.CreateServicePolicyResponse{ZitiServicePolicyId: f.policyID}, nil
}
func (f *fakeZitiManagementClient) GetServicePolicy(context.Context, *zitimanagementv1.GetServicePolicyRequest, ...grpc.CallOption) (*zitimanagementv1.GetServicePolicyResponse, error) {
	if f.servicePolicy != nil {
		return &zitimanagementv1.GetServicePolicyResponse{ServicePolicy: f.servicePolicy}, nil
	}
	return &zitimanagementv1.GetServicePolicyResponse{ServicePolicy: &zitimanagementv1.OpenZitiServicePolicy{ZitiServicePolicyId: f.policyID}}, nil
}
func (f *fakeZitiManagementClient) ListServicePolicies(context.Context, *zitimanagementv1.ListServicePoliciesRequest, ...grpc.CallOption) (*zitimanagementv1.ListServicePoliciesResponse, error) {
	return &zitimanagementv1.ListServicePoliciesResponse{}, nil
}
func (f *fakeZitiManagementClient) DeleteServicePolicy(context.Context, *zitimanagementv1.DeleteServicePolicyRequest, ...grpc.CallOption) (*zitimanagementv1.DeleteServicePolicyResponse, error) {
	f.deleteServicePolicyCalls++
	return &zitimanagementv1.DeleteServicePolicyResponse{}, nil
}

type fakeNotificationsClient struct{}

func (fakeNotificationsClient) Publish(context.Context, *notificationsv1.PublishRequest, ...grpc.CallOption) (*notificationsv1.PublishResponse, error) {
	return &notificationsv1.PublishResponse{}, nil
}

type fakeSecretsClient struct{}

func (fakeSecretsClient) ResolveSecretExists(context.Context, *secretsv1.ResolveSecretExistsRequest, ...grpc.CallOption) (*secretsv1.ResolveSecretExistsResponse, error) {
	return &secretsv1.ResolveSecretExistsResponse{Exists: true}, nil
}
