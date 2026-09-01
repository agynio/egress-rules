package server

import (
	"context"
	"errors"
	"fmt"

	egressv1 "github.com/agynio/egress/.gen/go/agynio/api/egress/v1"
	secretsv1 "github.com/agynio/egress/.gen/go/agynio/api/secrets/v1"
	"github.com/agynio/egress/internal/store"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) CreateEgressRule(ctx context.Context, req *egressv1.CreateEgressRuleRequest) (*egressv1.CreateEgressRuleResponse, error) {
	callerID, err := authenticatedIdentity(ctx)
	if err != nil {
		return nil, err
	}
	input, err := validateRuleInput(req.GetOrganizationId(), req.GetName(), req.GetDescription(), req.GetMatcher(), req.GetEffect(), req.GetUpstreamTls())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.requireOrgOwner(ctx, callerID, input.OrganizationID); err != nil {
		return nil, err
	}
	if err := s.validateSecrets(ctx, input.OrganizationID, input.SecretIDs); err != nil {
		return nil, err
	}
	if err := s.validatePrivateTarget(ctx, input.OrganizationID, input.Matcher, input.UpstreamTLS); err != nil {
		return nil, err
	}

	ruleID := uuid.New()
	// A private-target rule provisions no OpenZiti service of its own; it
	// rides the resource's, and its first rule flips the resource onto the
	// gateway instead.
	serviceID := ""
	if input.Matcher.GetPrivateResourceId() == "" {
		serviceID, err = s.provisionRuleService(ctx, ruleID, input.Matcher)
		if err != nil {
			return nil, err
		}
	}
	rule := store.Rule{
		ID:                ruleID,
		OrganizationID:    input.OrganizationID,
		Name:              input.Name,
		Description:       input.Description,
		Matcher:           input.Matcher,
		Effect:            input.Effect,
		UpstreamTLS:       input.UpstreamTLS,
		OpenZitiServiceID: serviceID,
	}
	if err := s.store.CreateRule(ctx, rule); err != nil {
		if cleanupErr := s.deleteRuleService(ctx, serviceID); cleanupErr != nil {
			return nil, cleanupErr
		}
		return nil, toStatusError(err)
	}
	stored, err := s.store.GetRule(ctx, ruleID)
	if err != nil {
		return nil, toStatusError(err)
	}
	if resourceID, err := uuid.Parse(stored.Matcher.GetPrivateResourceId()); err == nil {
		s.syncPrivateResourceMediation(ctx, resourceID)
	}
	s.publishRuleUpdated(ctx, stored.OrganizationID, stored.ID, "created")
	return &egressv1.CreateEgressRuleResponse{EgressRule: store.RuleToProto(stored)}, nil
}

func (s *Server) GetEgressRule(ctx context.Context, req *egressv1.GetEgressRuleRequest) (*egressv1.GetEgressRuleResponse, error) {
	callerID, err := authenticatedIdentity(ctx)
	if err != nil {
		return nil, err
	}
	ruleID, err := parseUUID(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	rule, err := s.store.GetRule(ctx, ruleID)
	if err != nil {
		return nil, toStatusError(err)
	}
	if err := s.requireOrgMember(ctx, callerID, rule.OrganizationID); err != nil {
		return nil, err
	}
	return &egressv1.GetEgressRuleResponse{EgressRule: store.RuleToProto(rule)}, nil
}

func (s *Server) ListEgressRules(ctx context.Context, req *egressv1.ListEgressRulesRequest) (*egressv1.ListEgressRulesResponse, error) {
	callerID, err := authenticatedIdentity(ctx)
	if err != nil {
		return nil, err
	}
	organizationID, err := parseUUID(req.GetOrganizationId(), "organization_id")
	if err != nil {
		return nil, err
	}
	if err := s.requireOrgMember(ctx, callerID, organizationID); err != nil {
		return nil, err
	}
	cursor, err := store.DecodePageCursor(req.GetPageToken())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	filter := store.RuleListFilter{}
	if req.PrivateResourceId != nil {
		resourceID, err := parseUUID(req.GetPrivateResourceId(), "private_resource_id")
		if err != nil {
			return nil, err
		}
		filter.PrivateResourceID = &resourceID
	}
	switch req.GetTargetKind() {
	case egressv1.EgressRuleTargetKind_EGRESS_RULE_TARGET_KIND_PUBLIC:
		filter.TargetKind = store.TargetKindPublic
	case egressv1.EgressRuleTargetKind_EGRESS_RULE_TARGET_KIND_PRIVATE:
		filter.TargetKind = store.TargetKindPrivate
	}
	result, err := s.store.ListRules(ctx, organizationID, filter, req.GetPageSize(), cursor)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &egressv1.ListEgressRulesResponse{EgressRules: rulesToProto(result.Rules), NextPageToken: store.EncodePageCursor(result.NextCursor)}, nil
}

func (s *Server) UpdateEgressRule(ctx context.Context, req *egressv1.UpdateEgressRuleRequest) (*egressv1.UpdateEgressRuleResponse, error) {
	callerID, err := authenticatedIdentity(ctx)
	if err != nil {
		return nil, err
	}
	ruleID, err := parseUUID(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	existing, err := s.store.GetRule(ctx, ruleID)
	if err != nil {
		return nil, toStatusError(err)
	}
	if err := s.requireOrgOwner(ctx, callerID, existing.OrganizationID); err != nil {
		return nil, err
	}
	updated := existing
	if req.Name != nil {
		updated.Name = req.GetName()
	}
	if req.Description != nil {
		updated.Description = req.GetDescription()
	}
	if req.GetMatcher() != nil || req.GetEffect() != nil || req.UpstreamTls != nil {
		matcher := updated.Matcher
		effect := updated.Effect
		upstreamTLS := updated.UpstreamTLS
		if req.GetMatcher() != nil {
			matcher = req.GetMatcher()
		}
		if req.GetEffect() != nil {
			effect = req.GetEffect()
		}
		if req.UpstreamTls != nil {
			// Presence with all fields empty clears the block.
			upstreamTLS = req.GetUpstreamTls()
		}
		input, err := validateRuleInput(existing.OrganizationID.String(), updated.Name, updated.Description, matcher, effect, upstreamTLS)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		// The target kind is immutable, and a private rule cannot be
		// repointed between resources; delete and recreate.
		if input.Matcher.GetPrivateResourceId() != existing.Matcher.GetPrivateResourceId() {
			return nil, status.Error(codes.InvalidArgument, "the matcher's destination kind is immutable; delete the rule and create a new one")
		}
		if err := s.validateSecrets(ctx, existing.OrganizationID, input.SecretIDs); err != nil {
			return nil, err
		}
		if req.UpstreamTls != nil {
			if err := s.validatePrivateTarget(ctx, existing.OrganizationID, input.Matcher, input.UpstreamTLS); err != nil {
				return nil, err
			}
		}
		updated.Name = input.Name
		updated.Description = input.Description
		updated.Matcher = input.Matcher
		updated.Effect = input.Effect
		updated.UpstreamTLS = input.UpstreamTLS
	}
	if req.GetMatcher() != nil && !updated.IsPrivateTarget() && !interceptV1ConfigsEqual(interceptV1Config(existing.Matcher), interceptV1Config(updated.Matcher)) {
		serviceID, err := s.updateRuleService(ctx, updated)
		if err != nil {
			return nil, err
		}
		updated.OpenZitiServiceID = serviceID
	}
	if err := s.store.UpdateRule(ctx, updated); err != nil {
		return nil, toStatusError(err)
	}
	stored, err := s.store.GetRule(ctx, ruleID)
	if err != nil {
		return nil, toStatusError(err)
	}
	s.publishRuleUpdated(ctx, stored.OrganizationID, stored.ID, "updated")
	return &egressv1.UpdateEgressRuleResponse{EgressRule: store.RuleToProto(stored)}, nil
}

func (s *Server) DeleteEgressRule(ctx context.Context, req *egressv1.DeleteEgressRuleRequest) (*egressv1.DeleteEgressRuleResponse, error) {
	callerID, err := authenticatedIdentity(ctx)
	if err != nil {
		return nil, err
	}
	ruleID, err := parseUUID(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	rule, err := s.store.GetRule(ctx, ruleID)
	if err != nil {
		return nil, toStatusError(err)
	}
	if err := s.requireOrgOwner(ctx, callerID, rule.OrganizationID); err != nil {
		return nil, err
	}
	count, err := s.store.CountAttachmentsByRule(ctx, ruleID)
	if err != nil {
		return nil, toStatusError(err)
	}
	if count > 0 {
		return nil, status.Error(codes.FailedPrecondition, "egress rule has attachments")
	}
	if err := s.store.DeleteRule(ctx, ruleID); err != nil {
		return nil, toStatusError(err)
	}
	if err := s.deleteRuleService(ctx, rule.OpenZitiServiceID); err != nil {
		return nil, err
	}
	// Deleting a resource's last rule returns it to the direct tunnel path.
	if resourceID, err := uuid.Parse(rule.Matcher.GetPrivateResourceId()); err == nil {
		s.syncPrivateResourceMediation(ctx, resourceID)
	}
	s.publishRuleUpdated(ctx, rule.OrganizationID, rule.ID, "deleted")
	return &egressv1.DeleteEgressRuleResponse{}, nil
}

func (s *Server) CreateEgressRuleAttachment(ctx context.Context, req *egressv1.CreateEgressRuleAttachmentRequest) (*egressv1.CreateEgressRuleAttachmentResponse, error) {
	callerID, err := authenticatedIdentity(ctx)
	if err != nil {
		return nil, err
	}
	ruleID, err := parseUUID(req.GetRuleId(), "rule_id")
	if err != nil {
		return nil, err
	}
	target, err := attachmentTargetFromRequest(req)
	if err != nil {
		return nil, err
	}
	rule, err := s.store.GetRule(ctx, ruleID)
	if err != nil {
		return nil, toStatusError(err)
	}
	if err := s.requireOrgMember(ctx, callerID, rule.OrganizationID); err != nil {
		return nil, err
	}
	if err := s.requireTargetConfigEdit(ctx, callerID, target); err != nil {
		return nil, err
	}
	if err := s.requireTargetInOrganization(ctx, rule.OrganizationID, target); err != nil {
		return nil, err
	}
	if _, err := s.store.GetAttachmentByRuleAndTarget(ctx, ruleID, target.kind, target.id); err == nil {
		return nil, toStatusError(store.ErrAttachmentExists)
	} else if !errors.Is(err, store.ErrAttachmentNotFound) {
		return nil, toStatusError(err)
	}
	if err := s.rejectInterceptCollision(ctx, rule, target); err != nil {
		return nil, err
	}
	// A private-target rule rides the resource's service; only a public one
	// has a per-rule service to reconcile.
	if !rule.IsPrivateTarget() {
		serviceID, err := s.reconcileRuleService(ctx, rule)
		if err != nil {
			return nil, err
		}
		if serviceID != rule.OpenZitiServiceID {
			if err := s.store.UpdateRuleServiceID(ctx, rule.ID, serviceID); err != nil {
				return nil, toStatusError(err)
			}
		}
		rule.OpenZitiServiceID = serviceID
	}
	policyID, err := s.provisionAttachmentPolicy(ctx, rule, target)
	if err != nil {
		return nil, err
	}
	attachmentID := uuid.New()
	attachment := store.Attachment{ID: attachmentID, RuleID: ruleID, OpenZitiDialPolicyID: policyID}
	if target.kind == targetKindEnvironment {
		id := target.id
		attachment.EnvironmentID = &id
	} else {
		id := target.id
		attachment.AgentID = &id
	}
	if err := s.store.CreateAttachment(ctx, attachment); err != nil {
		if cleanupErr := s.deleteAttachmentPolicy(ctx, policyID); cleanupErr != nil {
			return nil, cleanupErr
		}
		return nil, toStatusError(err)
	}
	stored, err := s.store.GetAttachment(ctx, attachmentID)
	if err != nil {
		return nil, toStatusError(err)
	}
	s.publishAttachmentUpdated(ctx, rule.OrganizationID, ruleID, stored.ID, target.id, "created")
	return &egressv1.CreateEgressRuleAttachmentResponse{EgressRuleAttachment: store.AttachmentToProto(stored)}, nil
}

func (s *Server) DeleteEgressRuleAttachment(ctx context.Context, req *egressv1.DeleteEgressRuleAttachmentRequest) (*egressv1.DeleteEgressRuleAttachmentResponse, error) {
	callerID, err := authenticatedIdentity(ctx)
	if err != nil {
		return nil, err
	}
	attachmentID, err := parseUUID(req.GetId(), "id")
	if err != nil {
		return nil, err
	}
	attachment, err := s.store.GetAttachment(ctx, attachmentID)
	if err != nil {
		return nil, toStatusError(err)
	}
	rule, err := s.store.GetRule(ctx, attachment.RuleID)
	if err != nil {
		return nil, toStatusError(err)
	}
	if err := s.requireOrgMember(ctx, callerID, rule.OrganizationID); err != nil {
		return nil, err
	}
	target, err := targetForAttachment(attachment)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if err := s.requireTargetConfigEdit(ctx, callerID, target); err != nil {
		return nil, err
	}
	if err := s.store.DeleteAttachment(ctx, attachmentID); err != nil {
		return nil, toStatusError(err)
	}
	if err := s.deleteAttachmentPolicy(ctx, attachment.OpenZitiDialPolicyID); err != nil {
		return nil, err
	}
	s.publishAttachmentUpdated(ctx, rule.OrganizationID, rule.ID, attachment.ID, target.id, "deleted")
	return &egressv1.DeleteEgressRuleAttachmentResponse{}, nil
}

func (s *Server) ListEgressRuleAttachments(ctx context.Context, req *egressv1.ListEgressRuleAttachmentsRequest) (*egressv1.ListEgressRuleAttachmentsResponse, error) {
	callerID, err := authenticatedIdentity(ctx)
	if err != nil {
		return nil, err
	}
	organizationID, err := parseUUID(req.GetOrganizationId(), "organization_id")
	if err != nil {
		return nil, err
	}
	var ruleID *uuid.UUID
	if req.RuleId != nil {
		id, err := parseUUID(req.GetRuleId(), "rule_id")
		if err != nil {
			return nil, err
		}
		rule, err := s.store.GetRule(ctx, id)
		if err != nil {
			return nil, toStatusError(err)
		}
		if rule.OrganizationID != organizationID {
			return nil, status.Error(codes.NotFound, store.ErrRuleNotFound.Error())
		}
		if err := s.requireOrgMember(ctx, callerID, rule.OrganizationID); err != nil {
			return nil, err
		}
		ruleID = &id
	}
	var agentID *uuid.UUID
	if req.AgentId != nil {
		id, err := parseUUID(req.GetAgentId(), "agent_id")
		if err != nil {
			return nil, err
		}
		if err := s.requireAgentConfigRead(ctx, callerID, id); err != nil {
			return nil, err
		}
		agentID = &id
	}
	if ruleID == nil && agentID == nil {
		if err := s.requireOrgMember(ctx, callerID, organizationID); err != nil {
			return nil, err
		}
	}
	cursor, err := store.DecodePageCursor(req.GetPageToken())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	result, err := s.store.ListAttachments(ctx, organizationID, ruleID, agentID, req.GetPageSize(), cursor)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &egressv1.ListEgressRuleAttachmentsResponse{EgressRuleAttachments: attachmentsToProto(result.Attachments), NextPageToken: store.EncodePageCursor(result.NextCursor)}, nil
}

// Internal-only, like the agent lookup: the Egress Gateway calls it on cache
// miss for a workload running an environment, sandboxes included.
func (s *Server) ListEgressRulesByEnvironment(ctx context.Context, req *egressv1.ListEgressRulesByEnvironmentRequest) (*egressv1.ListEgressRulesByEnvironmentResponse, error) {
	environmentID, err := parseUUID(req.GetEnvironmentId(), "environment_id")
	if err != nil {
		return nil, err
	}
	rules, err := s.store.ListRulesByEnvironment(ctx, environmentID)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &egressv1.ListEgressRulesByEnvironmentResponse{EgressRules: rulesToProto(rules), PrivateResources: s.privateResourceInfos(ctx, rules)}, nil
}

func (s *Server) ListEgressRulesByAgent(ctx context.Context, req *egressv1.ListEgressRulesByAgentRequest) (*egressv1.ListEgressRulesByAgentResponse, error) {
	agentID, err := parseUUID(req.GetAgentId(), "agent_id")
	if err != nil {
		return nil, err
	}
	rules, err := s.store.ListRulesByAgent(ctx, agentID)
	if err != nil {
		return nil, toStatusError(err)
	}
	return &egressv1.ListEgressRulesByAgentResponse{EgressRules: rulesToProto(rules), PrivateResources: s.privateResourceInfos(ctx, rules)}, nil
}

func (s *Server) CountRulesReferencingSecret(ctx context.Context, req *egressv1.CountRulesReferencingSecretRequest) (*egressv1.CountRulesReferencingSecretResponse, error) {
	secretID, err := parseUUID(req.GetSecretId(), "secret_id")
	if err != nil {
		return nil, err
	}
	count, ids, err := s.store.CountRulesReferencingSecret(ctx, secretID)
	if err != nil {
		return nil, toStatusError(err)
	}
	values := make([]string, 0, len(ids))
	for _, id := range ids {
		values = append(values, id.String())
	}
	return &egressv1.CountRulesReferencingSecretResponse{Count: count, EgressRuleIds: values}, nil
}

// Internal-only: the Networks service refuses to delete a private resource,
// or change its protocol to tcp, while rules name it.
func (s *Server) CountRulesReferencingPrivateResource(ctx context.Context, req *egressv1.CountRulesReferencingPrivateResourceRequest) (*egressv1.CountRulesReferencingPrivateResourceResponse, error) {
	resourceID, err := parseUUID(req.GetPrivateResourceId(), "private_resource_id")
	if err != nil {
		return nil, err
	}
	count, ids, err := s.store.CountRulesReferencingPrivateResource(ctx, resourceID)
	if err != nil {
		return nil, toStatusError(err)
	}
	values := make([]string, 0, len(ids))
	for _, id := range ids {
		values = append(values, id.String())
	}
	return &egressv1.CountRulesReferencingPrivateResourceResponse{Count: count, EgressRuleIds: values}, nil
}

// Internal-only: the Networks service re-derives desired mediation for an
// organization's resources each reconciliation pass.
func (s *Server) ListMediatedPrivateResources(ctx context.Context, req *egressv1.ListMediatedPrivateResourcesRequest) (*egressv1.ListMediatedPrivateResourcesResponse, error) {
	organizationID, err := parseUUID(req.GetOrganizationId(), "organization_id")
	if err != nil {
		return nil, err
	}
	ids, err := s.store.ListMediatedPrivateResourceIDs(ctx, organizationID)
	if err != nil {
		return nil, toStatusError(err)
	}
	values := make([]string, 0, len(ids))
	for _, id := range ids {
		values = append(values, id.String())
	}
	return &egressv1.ListMediatedPrivateResourcesResponse{PrivateResourceIds: values}, nil
}

// Internal-only: the Networks service fast-fails a hostname collision before
// granting a principal a private resource. The caller expands an agent to its
// environment and calls once per principal.
func (s *Server) ListAttachedRuleDomains(ctx context.Context, req *egressv1.ListAttachedRuleDomainsRequest) (*egressv1.ListAttachedRuleDomainsResponse, error) {
	var rules []store.Rule
	switch principal := req.GetPrincipal().(type) {
	case *egressv1.ListAttachedRuleDomainsRequest_AgentId:
		agentID, err := parseUUID(principal.AgentId, "agent_id")
		if err != nil {
			return nil, err
		}
		rules, err = s.store.ListRulesByAgent(ctx, agentID)
		if err != nil {
			return nil, toStatusError(err)
		}
	case *egressv1.ListAttachedRuleDomainsRequest_EnvironmentId:
		environmentID, err := parseUUID(principal.EnvironmentId, "environment_id")
		if err != nil {
			return nil, err
		}
		rules, err = s.store.ListRulesByEnvironment(ctx, environmentID)
		if err != nil {
			return nil, toStatusError(err)
		}
	default:
		return nil, status.Error(codes.InvalidArgument, "principal is required")
	}
	domains := make([]*egressv1.AttachedRuleDomain, 0, len(rules))
	for _, rule := range rules {
		if rule.IsPrivateTarget() {
			continue
		}
		domains = append(domains, &egressv1.AttachedRuleDomain{
			EgressRuleId:  rule.ID.String(),
			DomainPattern: rule.Matcher.GetDomainPattern(),
			Ports:         rule.Matcher.GetPorts(),
		})
	}
	return &egressv1.ListAttachedRuleDomainsResponse{Domains: domains}, nil
}

func (s *Server) validateSecrets(ctx context.Context, organizationID uuid.UUID, secretIDs []uuid.UUID) error {
	seen := map[uuid.UUID]struct{}{}
	for _, secretID := range secretIDs {
		if _, ok := seen[secretID]; ok {
			continue
		}
		seen[secretID] = struct{}{}
		resp, err := s.secretsClient.ResolveSecretExists(ctx, &secretsv1.ResolveSecretExistsRequest{Id: secretID.String()})
		if err != nil {
			return status.Errorf(codes.FailedPrecondition, "resolve secret %s: %v", secretID, err)
		}
		if !resp.GetExists() {
			return status.Errorf(codes.InvalidArgument, "secret %s does not exist", secretID)
		}
		if resp.GetOrganizationId() != organizationID.String() {
			return status.Errorf(codes.PermissionDenied, "secret %s belongs to another organization", secretID)
		}
	}
	return nil
}

func authenticatedIdentity(ctx context.Context) (uuid.UUID, error) {
	identityID, err := identityFromMetadata(ctx)
	if err != nil {
		return uuid.UUID{}, status.Errorf(codes.Unauthenticated, "unauthenticated: %v", err)
	}
	return identityID, nil
}

func parseUUID(value string, field string) (uuid.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil {
		return uuid.UUID{}, status.Errorf(codes.InvalidArgument, "%s: invalid uuid", field)
	}
	return id, nil
}

func rulesToProto(rules []store.Rule) []*egressv1.EgressRule {
	items := make([]*egressv1.EgressRule, 0, len(rules))
	for _, rule := range rules {
		items = append(items, store.RuleToProto(rule))
	}
	return items
}

func attachmentsToProto(attachments []store.Attachment) []*egressv1.EgressRuleAttachment {
	items := make([]*egressv1.EgressRuleAttachment, 0, len(attachments))
	for _, attachment := range attachments {
		items = append(items, store.AttachmentToProto(attachment))
	}
	return items
}

func toStatusError(err error) error {
	switch {
	case errors.Is(err, store.ErrRuleNotFound), errors.Is(err, store.ErrAttachmentNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, store.ErrRuleAlreadyExists), errors.Is(err, store.ErrAttachmentExists):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, store.ErrRuleHasAttachments):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return status.Error(codes.Internal, fmt.Sprintf("internal error: %v", err))
	}
}

// DeleteOrganizationResources removes the organization's egress rules and the
// attachments on them, along with the OpenZiti service and dial policy behind
// each. It is internal: Istio settles who may call it, so there is no
// permission check and no caller identity to check against. Step 5 of the
// organization teardown, after the agents whose attachments named these rules.
//
// Attachments go first: a rule with attachments refuses to be deleted, which is
// the invariant DeleteEgressRule enforces and this step honours rather than
// works around.
//
// The mediation sync and the change events that DeleteEgressRule fires are
// skipped. Both address an organization that carries on afterwards; this one
// does not, and the private resources they would sync against are removed by
// Networks in this same step.
//
// Idempotent by construction: a retried step lists nothing and deletes nothing.
func (s *Server) DeleteOrganizationResources(ctx context.Context, req *egressv1.DeleteOrganizationResourcesRequest) (*egressv1.DeleteOrganizationResourcesResponse, error) {
	organizationID, err := parseUUID(req.GetOrganizationId(), "organization_id")
	if err != nil {
		return nil, err
	}

	attachments, err := s.store.ListAttachmentsByOrganization(ctx, organizationID)
	if err != nil {
		return nil, toStatusError(err)
	}
	for _, attachment := range attachments {
		if err := s.store.DeleteAttachment(ctx, attachment.ID); err != nil {
			return nil, toStatusError(err)
		}
		if err := s.deleteAttachmentPolicy(ctx, attachment.OpenZitiDialPolicyID); err != nil {
			return nil, err
		}
	}

	rules, err := s.store.ListRulesByOrganization(ctx, organizationID)
	if err != nil {
		return nil, toStatusError(err)
	}
	for _, rule := range rules {
		if err := s.store.DeleteRule(ctx, rule.ID); err != nil {
			return nil, toStatusError(err)
		}
		if err := s.deleteRuleService(ctx, rule.OpenZitiServiceID); err != nil {
			return nil, err
		}
	}
	return &egressv1.DeleteOrganizationResourcesResponse{}, nil
}
