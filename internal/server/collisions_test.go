package server

import (
	"context"
	"strings"
	"testing"

	agentsv1 "github.com/agynio/egress/.gen/go/agynio/api/agents/v1"
	egressv1 "github.com/agynio/egress/.gen/go/agynio/api/egress/v1"
	networksv1 "github.com/agynio/egress/.gen/go/agynio/api/networks/v1"
	"github.com/agynio/egress/internal/store"
	"github.com/google/uuid"
	"google.golang.org/grpc"
)

type fakeAgentsClient struct {
	agents []*agentsv1.Agent
}

func (f *fakeAgentsClient) ListAgents(_ context.Context, _ *agentsv1.ListAgentsRequest, _ ...grpc.CallOption) (*agentsv1.ListAgentsResponse, error) {
	return &agentsv1.ListAgentsResponse{Agents: f.agents}, nil
}

func publicRuleFixture(orgID uuid.UUID, domain string, ports ...int32) store.Rule {
	if len(ports) == 0 {
		ports = []int32{80, 443}
	}
	return store.Rule{
		ID:             uuid.New(),
		OrganizationID: orgID,
		Matcher:        &egressv1.EgressRuleMatcher{DomainPattern: domain, Ports: ports},
		Effect:         &egressv1.EgressRuleEffect{Action: egressv1.EgressRuleAction_EGRESS_RULE_ACTION_ALLOW.Enum()},
	}
}

func agentFixture(agentID uuid.UUID, environmentID uuid.UUID) *agentsv1.Agent {
	return &agentsv1.Agent{Meta: &agentsv1.EntityMeta{Id: agentID.String()}, EnvironmentId: environmentID.String()}
}

// The state no write-time check sees: a group grant completes the collision
// with a rule attached directly to the agent.
func TestCollisionDetectedThroughGroupGrant(t *testing.T) {
	orgID := uuid.New()
	agentID := uuid.New()
	groupID := uuid.New()
	resourceID := uuid.NewString()
	rule := publicRuleFixture(orgID, "gitlab.corp")
	networks := &fakeNetworksClient{reachable: []*networksv1.ReachablePrivateResource{{
		Id:             resourceID,
		InterceptHost:  "gitlab.corp",
		InterceptPorts: []int32{443},
		Grants:         []*networksv1.ReachablePrivateResourceGrant{{PrincipalType: networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_GROUP, PrincipalId: groupID.String()}},
	}}}
	server := New(Options{
		Store:          &fakeRuleStore{},
		NetworksClient: networks,
		AgentsClient:   &fakeAgentsClient{agents: []*agentsv1.Agent{agentFixture(agentID, uuid.New())}},
	})

	collisions := server.collectInterceptCollisions(context.Background(),
		[]store.Rule{rule},
		[]store.Attachment{{ID: uuid.New(), RuleID: rule.ID, AgentID: &agentID}},
	)
	if len(collisions) != 1 {
		t.Fatalf("expected 1 collision, got %+v", collisions)
	}
	collision := collisions[0]
	if collision.AgentID != agentID || collision.RuleID != rule.ID || collision.ResourceID != resourceID {
		t.Fatalf("unexpected collision %+v", collision)
	}
	report := collision.String()
	if !strings.Contains(report, "granted to group "+groupID.String()) || !strings.Contains(report, "attached to the agent") {
		t.Fatalf("report must name how each side was acquired: %s", report)
	}
}

// Repointing an agent at an environment the rule is attached to: the rule
// reaches the agent through the environment, the grant is the agent's own.
func TestCollisionDetectedThroughEnvironmentAttachment(t *testing.T) {
	orgID := uuid.New()
	agentID := uuid.New()
	environmentID := uuid.New()
	resourceID := uuid.NewString()
	rule := publicRuleFixture(orgID, "*.corp")
	networks := &fakeNetworksClient{reachable: []*networksv1.ReachablePrivateResource{{
		Id:             resourceID,
		InterceptHost:  "gitlab.corp",
		InterceptPorts: []int32{443},
		Grants:         []*networksv1.ReachablePrivateResourceGrant{{PrincipalType: networksv1.PrivateResourceAccessPrincipalType_PRIVATE_RESOURCE_ACCESS_PRINCIPAL_TYPE_AGENT, PrincipalId: agentID.String()}},
	}}}
	server := New(Options{
		Store:          &fakeRuleStore{},
		NetworksClient: networks,
		AgentsClient:   &fakeAgentsClient{agents: []*agentsv1.Agent{agentFixture(agentID, environmentID)}},
	})

	collisions := server.collectInterceptCollisions(context.Background(),
		[]store.Rule{rule},
		[]store.Attachment{{ID: uuid.New(), RuleID: rule.ID, EnvironmentID: &environmentID}},
	)
	if len(collisions) != 1 {
		t.Fatalf("expected 1 collision, got %+v", collisions)
	}
	if !strings.Contains(collisions[0].String(), "attached to environment "+environmentID.String()) {
		t.Fatalf("report must name the environment attachment: %s", collisions[0].String())
	}
}

// A private-target attachment grants the same reachability a grant does, so
// it completes the collision with a public rule the same way.
func TestCollisionDetectedThroughPrivateRuleAttachment(t *testing.T) {
	orgID := uuid.New()
	agentID := uuid.New()
	resourceID := uuid.NewString()
	publicRule := publicRuleFixture(orgID, "gitlab.corp")
	privateTargetRule := store.Rule{
		ID:             uuid.New(),
		OrganizationID: orgID,
		Matcher:        &egressv1.EgressRuleMatcher{PrivateResourceId: resourceID},
		Effect:         &egressv1.EgressRuleEffect{Action: egressv1.EgressRuleAction_EGRESS_RULE_ACTION_ALLOW.Enum()},
	}
	resourceUUID := uuid.MustParse(resourceID)
	networks := &fakeNetworksClient{resources: map[string]*networksv1.PrivateResource{
		resourceID: privateResourceFixture(resourceUUID, orgID, networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_HTTPS),
	}}
	server := New(Options{
		Store:          &fakeRuleStore{},
		NetworksClient: networks,
		AgentsClient:   &fakeAgentsClient{agents: []*agentsv1.Agent{agentFixture(agentID, uuid.New())}},
	})

	collisions := server.collectInterceptCollisions(context.Background(),
		[]store.Rule{publicRule, privateTargetRule},
		[]store.Attachment{
			{ID: uuid.New(), RuleID: publicRule.ID, AgentID: &agentID},
			{ID: uuid.New(), RuleID: privateTargetRule.ID, AgentID: &agentID},
		},
	)
	if len(collisions) != 1 {
		t.Fatalf("expected 1 collision, got %+v", collisions)
	}
	if !strings.Contains(collisions[0].String(), "egress rule "+privateTargetRule.ID.String()) {
		t.Fatalf("report must name the private rule attachment: %s", collisions[0].String())
	}
}

// Non-overlapping ports and unrelated hostnames are not collisions.
func TestNoCollisionWithoutOverlap(t *testing.T) {
	orgID := uuid.New()
	agentID := uuid.New()
	rule := publicRuleFixture(orgID, "gitlab.corp", 8080)
	networks := &fakeNetworksClient{reachable: []*networksv1.ReachablePrivateResource{
		{Id: uuid.NewString(), InterceptHost: "gitlab.corp", InterceptPorts: []int32{443}},
		{Id: uuid.NewString(), InterceptHost: "jira.corp", InterceptPorts: []int32{8080}},
	}}
	server := New(Options{
		Store:          &fakeRuleStore{},
		NetworksClient: networks,
		AgentsClient:   &fakeAgentsClient{agents: []*agentsv1.Agent{agentFixture(agentID, uuid.New())}},
	})

	collisions := server.collectInterceptCollisions(context.Background(),
		[]store.Rule{rule},
		[]store.Attachment{{ID: uuid.New(), RuleID: rule.ID, AgentID: &agentID}},
	)
	if len(collisions) != 0 {
		t.Fatalf("expected no collisions, got %+v", collisions)
	}
}
