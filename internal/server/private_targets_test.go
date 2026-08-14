package server

import (
	"context"
	"testing"

	egressv1 "github.com/agynio/egress/.gen/go/agynio/api/egress/v1"
	networksv1 "github.com/agynio/egress/.gen/go/agynio/api/networks/v1"
	"github.com/agynio/egress/internal/store"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeNetworksClient struct {
	resources      map[string]*networksv1.PrivateResource
	getErr         error
	mediationCalls []*networksv1.SetPrivateResourceMediationRequest
	reachable      []*networksv1.ReachablePrivateResource
	reachableErr   error
}

func (f *fakeNetworksClient) GetPrivateResource(_ context.Context, req *networksv1.GetPrivateResourceRequest, _ ...grpc.CallOption) (*networksv1.GetPrivateResourceResponse, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	resource, ok := f.resources[req.GetId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "private resource not found")
	}
	return &networksv1.GetPrivateResourceResponse{PrivateResource: resource}, nil
}

func (f *fakeNetworksClient) SetPrivateResourceMediation(_ context.Context, req *networksv1.SetPrivateResourceMediationRequest, _ ...grpc.CallOption) (*networksv1.SetPrivateResourceMediationResponse, error) {
	f.mediationCalls = append(f.mediationCalls, req)
	return &networksv1.SetPrivateResourceMediationResponse{}, nil
}

func (f *fakeNetworksClient) ListPrivateResourcesReachableBy(_ context.Context, _ *networksv1.ListPrivateResourcesReachableByRequest, _ ...grpc.CallOption) (*networksv1.ListPrivateResourcesReachableByResponse, error) {
	if f.reachableErr != nil {
		return nil, f.reachableErr
	}
	return &networksv1.ListPrivateResourcesReachableByResponse{PrivateResources: f.reachable}, nil
}

func privateResourceFixture(id uuid.UUID, orgID uuid.UUID, protocol networksv1.PrivateResourceProtocol) *networksv1.PrivateResource {
	return &networksv1.PrivateResource{
		Meta:           &networksv1.EntityMeta{Id: id.String()},
		OrganizationId: orgID.String(),
		Protocol:       protocol,
		InterceptHost:  "gitlab.corp",
		InterceptPorts: []int32{443},
	}
}

func privateRuleServer(t *testing.T, networks *fakeNetworksClient, orgID uuid.UUID, callerID uuid.UUID) (*Server, *fakeRuleStore, *fakeZitiManagementClient) {
	t.Helper()
	storeFake := &fakeRuleStore{}
	ziti := &fakeZitiManagementClient{serviceID: "ziti-service", policyID: "ziti-policy"}
	authz := &fakeAuthorizationClient{allowed: map[string]bool{
		tupleKey("identity:"+callerID.String(), organizationOwnerRelation, "organization:"+orgID.String()):  true,
		tupleKey("identity:"+callerID.String(), organizationMemberRelation, "organization:"+orgID.String()): true,
	}}
	server := New(Options{
		Store:               storeFake,
		AuthorizationClient: authz,
		SecretsClient:       &fakeSecretsClient{},
		NotificationsClient: &fakeNotificationsClient{},
		ZitiClient:          ziti,
		NetworksClient:      networks,
	})
	return server, storeFake, ziti
}

func TestCreatePrivateRuleSkipsServiceAndFlipsMediation(t *testing.T) {
	orgID := uuid.New()
	callerID := uuid.New()
	resourceID := uuid.New()
	networks := &fakeNetworksClient{resources: map[string]*networksv1.PrivateResource{
		resourceID.String(): privateResourceFixture(resourceID, orgID, networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_HTTPS),
	}}
	server, storeFake, ziti := privateRuleServer(t, networks, orgID, callerID)

	response, err := server.CreateEgressRule(incomingIdentityContext(callerID), &egressv1.CreateEgressRuleRequest{
		OrganizationId: orgID.String(),
		Name:           "gitlab-token",
		Matcher:        &egressv1.EgressRuleMatcher{PrivateResourceId: resourceID.String()},
		Effect:         allowEffect(),
	})
	if err != nil {
		t.Fatalf("CreateEgressRule: %v", err)
	}
	if got := response.GetEgressRule().GetMatcher().GetPrivateResourceId(); got != resourceID.String() {
		t.Fatalf("unexpected private_resource_id %s", got)
	}
	if ziti.createServiceCalls != 0 {
		t.Fatalf("a private-target rule must not provision an OpenZiti service, got %d creates", ziti.createServiceCalls)
	}
	if storeFake.created == nil || storeFake.created.OpenZitiServiceID != "" {
		t.Fatalf("expected the rule stored without a service id, got %+v", storeFake.created)
	}
	if len(networks.mediationCalls) != 1 || networks.mediationCalls[0].GetMediation() != networksv1.PrivateResourceMediation_PRIVATE_RESOURCE_MEDIATION_EGRESS_GATEWAY {
		t.Fatalf("expected one egress_gateway mediation call, got %+v", networks.mediationCalls)
	}
}

func TestCreatePrivateRuleRefusesTCPResourceAndForeignOrg(t *testing.T) {
	orgID := uuid.New()
	callerID := uuid.New()
	tcpResourceID := uuid.New()
	foreignResourceID := uuid.New()
	networks := &fakeNetworksClient{resources: map[string]*networksv1.PrivateResource{
		tcpResourceID.String():     privateResourceFixture(tcpResourceID, orgID, networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_TCP),
		foreignResourceID.String(): privateResourceFixture(foreignResourceID, uuid.New(), networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_HTTPS),
	}}
	server, _, _ := privateRuleServer(t, networks, orgID, callerID)

	_, err := server.CreateEgressRule(incomingIdentityContext(callerID), &egressv1.CreateEgressRuleRequest{
		OrganizationId: orgID.String(),
		Matcher:        &egressv1.EgressRuleMatcher{PrivateResourceId: tcpResourceID.String()},
		Effect:         allowEffect(),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for a tcp resource, got %v", err)
	}

	_, err = server.CreateEgressRule(incomingIdentityContext(callerID), &egressv1.CreateEgressRuleRequest{
		OrganizationId: orgID.String(),
		Matcher:        &egressv1.EgressRuleMatcher{PrivateResourceId: foreignResourceID.String()},
		Effect:         allowEffect(),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for a foreign resource, got %v", err)
	}

	if len(networks.mediationCalls) != 0 {
		t.Fatalf("a refused rule must not flip mediation, got %+v", networks.mediationCalls)
	}
}

func TestCreatePrivateRuleRefusesUpstreamTLSOnHTTPResource(t *testing.T) {
	orgID := uuid.New()
	callerID := uuid.New()
	resourceID := uuid.New()
	networks := &fakeNetworksClient{resources: map[string]*networksv1.PrivateResource{
		resourceID.String(): privateResourceFixture(resourceID, orgID, networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_HTTP),
	}}
	server, _, _ := privateRuleServer(t, networks, orgID, callerID)

	_, err := server.CreateEgressRule(incomingIdentityContext(callerID), &egressv1.CreateEgressRuleRequest{
		OrganizationId: orgID.String(),
		Matcher:        &egressv1.EgressRuleMatcher{PrivateResourceId: resourceID.String()},
		Effect:         allowEffect(),
		UpstreamTls:    &egressv1.EgressRuleUpstreamTls{ServerName: "gitlab.internal"},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for upstream_tls on an http resource, got %v", err)
	}
}

func TestDeleteLastPrivateRuleReturnsResourceToTunnel(t *testing.T) {
	orgID := uuid.New()
	callerID := uuid.New()
	resourceID := uuid.New()
	networks := &fakeNetworksClient{resources: map[string]*networksv1.PrivateResource{
		resourceID.String(): privateResourceFixture(resourceID, orgID, networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_HTTPS),
	}}
	server, storeFake, _ := privateRuleServer(t, networks, orgID, callerID)
	ruleID := uuid.New()
	storeFake.rule = store.Rule{
		ID:             ruleID,
		OrganizationID: orgID,
		Matcher:        &egressv1.EgressRuleMatcher{PrivateResourceId: resourceID.String()},
		Effect:         allowEffect(),
	}

	if _, err := server.DeleteEgressRule(incomingIdentityContext(callerID), &egressv1.DeleteEgressRuleRequest{Id: ruleID.String()}); err != nil {
		t.Fatalf("DeleteEgressRule: %v", err)
	}
	if len(networks.mediationCalls) != 1 || networks.mediationCalls[0].GetMediation() != networksv1.PrivateResourceMediation_PRIVATE_RESOURCE_MEDIATION_TUNNEL {
		t.Fatalf("expected one tunnel mediation call, got %+v", networks.mediationCalls)
	}
}

func TestMatcherValidationRejectsAmbiguousDestinations(t *testing.T) {
	if _, err := validateMatcher(&egressv1.EgressRuleMatcher{}); err == nil {
		t.Fatal("expected an empty matcher to be rejected")
	}
	if _, err := validateMatcher(&egressv1.EgressRuleMatcher{DomainPattern: "api.example.com", PrivateResourceId: uuid.NewString()}); err == nil {
		t.Fatal("expected both destinations to be rejected")
	}
	if _, err := validateMatcher(&egressv1.EgressRuleMatcher{PrivateResourceId: uuid.NewString(), Ports: []int32{443}}); err == nil {
		t.Fatal("expected ports on a private target to be rejected")
	}
	matcher, err := validateMatcher(&egressv1.EgressRuleMatcher{PrivateResourceId: uuid.NewString(), Methods: []string{"get"}})
	if err != nil {
		t.Fatalf("validateMatcher: %v", err)
	}
	if len(matcher.GetPorts()) != 0 {
		t.Fatalf("a private matcher must not gain default ports, got %v", matcher.GetPorts())
	}
}

func TestAttachPublicRuleFastFailsOnInterceptCollision(t *testing.T) {
	orgID := uuid.New()
	callerID := uuid.New()
	agentID := uuid.New()
	ruleID := uuid.New()
	resourceID := uuid.New()
	networks := &fakeNetworksClient{reachable: []*networksv1.ReachablePrivateResource{{
		Id:             resourceID.String(),
		InterceptHost:  "gitlab.corp",
		InterceptPorts: []int32{443},
	}}}
	server, storeFake, _ := privateRuleServer(t, networks, orgID, callerID)
	storeFake.rule = store.Rule{
		ID:                ruleID,
		OrganizationID:    orgID,
		Matcher:           &egressv1.EgressRuleMatcher{DomainPattern: "gitlab.corp", Ports: []int32{80, 443}},
		Effect:            allowEffect(),
		OpenZitiServiceID: "ziti-service",
	}
	authz := server.authorizationClient.(*fakeAuthorizationClient)
	authz.allowed[tupleKey("identity:"+callerID.String(), agentCanEditConfigRelation, "agent:"+agentID.String())] = true
	authz.allowed[tupleKey("organization:"+orgID.String(), agentOrgRelation, "agent:"+agentID.String())] = true

	_, err := server.CreateEgressRuleAttachment(incomingIdentityContext(callerID), &egressv1.CreateEgressRuleAttachmentRequest{
		RuleId: ruleID.String(),
		Target: &egressv1.CreateEgressRuleAttachmentRequest_AgentTargetId{AgentTargetId: agentID.String()},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition on intercept collision, got %v", err)
	}

	// The check is best-effort: an unreachable Networks service skips it.
	networks.reachableErr = status.Error(codes.Unavailable, "down")
	if _, err := server.CreateEgressRuleAttachment(incomingIdentityContext(callerID), &egressv1.CreateEgressRuleAttachmentRequest{
		RuleId: ruleID.String(),
		Target: &egressv1.CreateEgressRuleAttachmentRequest_AgentTargetId{AgentTargetId: agentID.String()},
	}); err != nil {
		t.Fatalf("best-effort check must not block on outage: %v", err)
	}
}

func TestAttachPrivateRuleUsesResourceRoleWithoutServiceReconcile(t *testing.T) {
	orgID := uuid.New()
	callerID := uuid.New()
	agentID := uuid.New()
	ruleID := uuid.New()
	resourceID := uuid.New()
	networks := &fakeNetworksClient{resources: map[string]*networksv1.PrivateResource{
		resourceID.String(): privateResourceFixture(resourceID, orgID, networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_HTTPS),
	}}
	server, storeFake, ziti := privateRuleServer(t, networks, orgID, callerID)
	storeFake.rule = store.Rule{
		ID:             ruleID,
		OrganizationID: orgID,
		Matcher:        &egressv1.EgressRuleMatcher{PrivateResourceId: resourceID.String()},
		Effect:         allowEffect(),
	}
	authz := server.authorizationClient.(*fakeAuthorizationClient)
	authz.allowed[tupleKey("identity:"+callerID.String(), agentCanEditConfigRelation, "agent:"+agentID.String())] = true
	authz.allowed[tupleKey("organization:"+orgID.String(), agentOrgRelation, "agent:"+agentID.String())] = true

	if _, err := server.CreateEgressRuleAttachment(incomingIdentityContext(callerID), &egressv1.CreateEgressRuleAttachmentRequest{
		RuleId: ruleID.String(),
		Target: &egressv1.CreateEgressRuleAttachmentRequest_AgentTargetId{AgentTargetId: agentID.String()},
	}); err != nil {
		t.Fatalf("CreateEgressRuleAttachment: %v", err)
	}
	if ziti.createServiceCalls != 0 || ziti.getServiceCalls != 0 {
		t.Fatalf("a private-target attachment must not touch the rule service, got %d creates %d gets", ziti.createServiceCalls, ziti.getServiceCalls)
	}
	if ziti.lastPolicy == nil || ziti.lastPolicy.GetServiceRoles()[0] != "#private-resource-"+resourceID.String() {
		t.Fatalf("expected the policy to select the resource role, got %+v", ziti.lastPolicy)
	}
}

func TestLookupResponsesCarryPrivateResourceInfo(t *testing.T) {
	orgID := uuid.New()
	resourceID := uuid.New()
	agentID := uuid.New()
	networks := &fakeNetworksClient{resources: map[string]*networksv1.PrivateResource{
		resourceID.String(): privateResourceFixture(resourceID, orgID, networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_HTTPS),
	}}
	storeFake := &fakeRuleStore{rulesByAgent: []store.Rule{{
		ID:             uuid.New(),
		OrganizationID: orgID,
		Matcher:        &egressv1.EgressRuleMatcher{PrivateResourceId: resourceID.String()},
		Effect:         allowEffect(),
	}}}
	server := New(Options{Store: storeFake, NetworksClient: networks})

	response, err := server.ListEgressRulesByAgent(context.Background(), &egressv1.ListEgressRulesByAgentRequest{AgentId: agentID.String()})
	if err != nil {
		t.Fatalf("ListEgressRulesByAgent: %v", err)
	}
	info := response.GetPrivateResources()[resourceID.String()]
	if info.GetInterceptHost() != "gitlab.corp" || info.GetProtocol() != egressv1.EgressPrivateResourceProtocol_EGRESS_PRIVATE_RESOURCE_PROTOCOL_HTTPS {
		t.Fatalf("unexpected private resource info %+v", info)
	}

	// A resource that cannot be resolved is omitted, not guessed at.
	networks.getErr = status.Error(codes.Unavailable, "down")
	response, err = server.ListEgressRulesByAgent(context.Background(), &egressv1.ListEgressRulesByAgentRequest{AgentId: agentID.String()})
	if err != nil {
		t.Fatalf("ListEgressRulesByAgent: %v", err)
	}
	if len(response.GetPrivateResources()) != 0 {
		t.Fatalf("expected no resource info on failure, got %+v", response.GetPrivateResources())
	}
	if len(response.GetEgressRules()) != 1 {
		t.Fatalf("the rules themselves must still be served, got %d", len(response.GetEgressRules()))
	}
}
