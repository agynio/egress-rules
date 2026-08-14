package server

import (
	"context"
	"fmt"
	"log"
	"strings"

	agentsv1 "github.com/agynio/egress/.gen/go/agynio/api/agents/v1"
	networksv1 "github.com/agynio/egress/.gen/go/agynio/api/networks/v1"
	"github.com/agynio/egress/internal/store"
	"github.com/google/uuid"
)

// interceptCollision is one identity authorized for two overlapping
// interceptions: a public rule's domain and a private resource's hostname.
// Reported, never repaired -- which side the operator meant is not inferable,
// and revoking either would cut off working traffic.
type interceptCollision struct {
	AgentID       uuid.UUID
	RuleID        uuid.UUID
	DomainPattern string
	RuleVia       string
	ResourceID    string
	InterceptHost string
	AccessVia     []string
}

func (c interceptCollision) String() string {
	return fmt.Sprintf("intercept collision: agent %s holds egress rule %s for %s (%s) and can dial private resource %s intercepting the same hostname (%s); its dials to %s are ambiguous",
		c.AgentID, c.RuleID, c.DomainPattern, c.RuleVia, c.ResourceID, strings.Join(c.AccessVia, ", "), c.InterceptHost)
}

// reportInterceptCollisions walks every agent that an attached public rule
// reaches -- directly or through its environment -- and reports each one that
// can also dial a private resource whose interception overlaps the rule's.
// No write-time check can prevent this state: the authorization is assembled
// by five write paths across four services, so each pass detects what the
// fast-fails could not see. Best-effort throughout; a failed lookup shrinks
// the report rather than failing the pass.
func (s *Server) reportInterceptCollisions(ctx context.Context, rules []store.Rule, attachments []store.Attachment) {
	for _, collision := range s.collectInterceptCollisions(ctx, rules, attachments) {
		log.Print(collision.String())
	}
}

func (s *Server) collectInterceptCollisions(ctx context.Context, rules []store.Rule, attachments []store.Attachment) []interceptCollision {
	if s.networksClient == nil || len(attachments) == 0 {
		return nil
	}
	rulesByID := make(map[uuid.UUID]store.Rule, len(rules))
	organizations := map[uuid.UUID]bool{}
	for _, rule := range rules {
		rulesByID[rule.ID] = rule
	}
	rulesByAgent := map[uuid.UUID][]attachedRule{}
	rulesByEnvironment := map[uuid.UUID][]attachedRule{}
	for _, attachment := range attachments {
		rule, ok := rulesByID[attachment.RuleID]
		if !ok {
			continue
		}
		organizations[rule.OrganizationID] = true
		switch {
		case attachment.AgentID != nil:
			rulesByAgent[*attachment.AgentID] = append(rulesByAgent[*attachment.AgentID], attachedRule{rule: rule, via: "attached to the agent"})
		case attachment.EnvironmentID != nil:
			rulesByEnvironment[*attachment.EnvironmentID] = append(rulesByEnvironment[*attachment.EnvironmentID], attachedRule{rule: rule, via: fmt.Sprintf("attached to environment %s", *attachment.EnvironmentID)})
		}
	}
	collisions := []interceptCollision{}
	resourceCache := map[string]*networksv1.PrivateResource{}
	seen := map[string]bool{}
	for _, agent := range s.listAgents(ctx, organizations) {
		agentID, err := uuid.Parse(agent.GetMeta().GetId())
		if err != nil {
			continue
		}
		effective := append([]attachedRule{}, rulesByAgent[agentID]...)
		if environmentID, err := uuid.Parse(agent.GetEnvironmentId()); err == nil {
			effective = append(effective, rulesByEnvironment[environmentID]...)
		}
		publicRules := []attachedRule{}
		privateRules := []attachedRule{}
		for _, attached := range effective {
			if attached.rule.IsPrivateTarget() {
				privateRules = append(privateRules, attached)
			} else {
				publicRules = append(publicRules, attached)
			}
		}
		if len(publicRules) == 0 {
			continue
		}
		for _, reachable := range s.reachableResources(ctx, agentID, privateRules, resourceCache) {
			for _, attached := range publicRules {
				if !domainPatternMatchesHost(attached.rule.Matcher.GetDomainPattern(), reachable.interceptHost) || !portsOverlap(attached.rule.Matcher.GetPorts(), reachable.interceptPorts) {
					continue
				}
				key := fmt.Sprintf("%s|%s|%s", agentID, attached.rule.ID, reachable.id)
				if seen[key] {
					continue
				}
				seen[key] = true
				collisions = append(collisions, interceptCollision{
					AgentID:       agentID,
					RuleID:        attached.rule.ID,
					DomainPattern: attached.rule.Matcher.GetDomainPattern(),
					RuleVia:       attached.via,
					ResourceID:    reachable.id,
					InterceptHost: reachable.interceptHost,
					AccessVia:     reachable.via,
				})
			}
		}
	}
	return collisions
}

// listAgents enumerates the agents of every organization holding attached
// rules; the listing carries each agent's environment, so environment
// attachments expand without a per-agent lookup.
func (s *Server) listAgents(ctx context.Context, organizations map[uuid.UUID]bool) []*agentsv1.Agent {
	if s.agentsClient == nil {
		return nil
	}
	agents := []*agentsv1.Agent{}
	for organizationID := range organizations {
		pageToken := ""
		for {
			response, err := s.agentsClient.ListAgents(ctx, &agentsv1.ListAgentsRequest{OrganizationId: organizationID.String(), PageToken: pageToken})
			if err != nil {
				log.Printf("list agents for organization %s failed: %v", organizationID, err)
				break
			}
			agents = append(agents, response.GetAgents()...)
			pageToken = response.GetNextPageToken()
			if pageToken == "" {
				break
			}
		}
	}
	return agents
}

// attachedRule pairs a rule with how it reaches the identity under report.
type attachedRule struct {
	rule store.Rule
	via  string
}

type reachableResource struct {
	id             string
	interceptHost  string
	interceptPorts []int32
	via            []string
}

// reachableResources is everything the agent can dial: grants expanded by the
// Networks service through the agent's groups and environment, plus the
// private-target rules reaching the agent -- an attachment grants the same
// reachability a grant does, so it collides the same way.
func (s *Server) reachableResources(ctx context.Context, agentID uuid.UUID, privateRules []attachedRule, resourceCache map[string]*networksv1.PrivateResource) []reachableResource {
	byID := map[string]*reachableResource{}
	ordered := []string{}
	response, err := s.networksClient.ListPrivateResourcesReachableBy(ctx, &networksv1.ListPrivateResourcesReachableByRequest{
		Principal: &networksv1.ListPrivateResourcesReachableByRequest_AgentId{AgentId: agentID.String()},
	})
	if err != nil {
		log.Printf("list private resources reachable by agent %s failed: %v", agentID, err)
	} else {
		for _, resource := range response.GetPrivateResources() {
			entry := &reachableResource{id: resource.GetId(), interceptHost: resource.GetInterceptHost(), interceptPorts: resource.GetInterceptPorts()}
			for _, grant := range resource.GetGrants() {
				entry.via = append(entry.via, fmt.Sprintf("granted to %s %s", strings.TrimPrefix(strings.ToLower(grant.GetPrincipalType().String()), "private_resource_access_principal_type_"), grant.GetPrincipalId()))
			}
			byID[entry.id] = entry
			ordered = append(ordered, entry.id)
		}
	}
	for _, attached := range privateRules {
		resourceID := attached.rule.Matcher.GetPrivateResourceId()
		resource, ok := resourceCache[resourceID]
		if !ok {
			fetched, err := s.networksClient.GetPrivateResource(ctx, &networksv1.GetPrivateResourceRequest{Id: resourceID})
			if err != nil {
				log.Printf("resolve private resource %s for collision report failed: %v", resourceID, err)
				continue
			}
			resource = fetched.GetPrivateResource()
			resourceCache[resourceID] = resource
		}
		via := fmt.Sprintf("egress rule %s %s", attached.rule.ID, attached.via)
		if entry, exists := byID[resourceID]; exists {
			entry.via = append(entry.via, via)
			continue
		}
		entry := &reachableResource{id: resourceID, interceptHost: resource.GetInterceptHost(), interceptPorts: resource.GetInterceptPorts(), via: []string{via}}
		byID[resourceID] = entry
		ordered = append(ordered, resourceID)
	}
	resources := make([]reachableResource, 0, len(ordered))
	for _, id := range ordered {
		resources = append(resources, *byID[id])
	}
	return resources
}
