package server

import (
	"context"
	"log"
	"strings"

	egressv1 "github.com/agynio/egress/.gen/go/agynio/api/egress/v1"
	networksv1 "github.com/agynio/egress/.gen/go/agynio/api/networks/v1"
	"github.com/agynio/egress/internal/store"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// The Networks service authorizes GetPrivateResource by the caller's
// organization membership; validation runs inside an authenticated rule
// write, so the caller rides along.
func forwardCallerIdentity(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	values := md.Get(identityMetadata)
	if len(values) == 0 {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, identityMetadata, values[0])
}

// validatePrivateTarget resolves the matcher's private resource and enforces
// what a rule may name: a resource in the rule's organization with protocol
// http or https, and upstream_tls only on an https one.
func (s *Server) validatePrivateTarget(ctx context.Context, organizationID uuid.UUID, matcher *egressv1.EgressRuleMatcher, upstreamTLS *egressv1.EgressRuleUpstreamTls) error {
	if matcher.GetPrivateResourceId() == "" {
		return nil
	}
	if s.networksClient == nil {
		return status.Error(codes.Internal, "private targets require the networks service")
	}
	response, err := s.networksClient.GetPrivateResource(forwardCallerIdentity(ctx), &networksv1.GetPrivateResourceRequest{Id: matcher.GetPrivateResourceId()})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return status.Errorf(codes.InvalidArgument, "matcher.private_resource_id: private resource %s does not exist", matcher.GetPrivateResourceId())
		}
		return status.Errorf(codes.FailedPrecondition, "resolve private resource %s: %v", matcher.GetPrivateResourceId(), err)
	}
	resource := response.GetPrivateResource()
	if resource.GetOrganizationId() != organizationID.String() {
		return status.Errorf(codes.PermissionDenied, "private resource %s belongs to another organization", matcher.GetPrivateResourceId())
	}
	switch resource.GetProtocol() {
	case networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_HTTPS:
	case networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_HTTP:
		if upstreamTLS != nil {
			return status.Error(codes.InvalidArgument, "upstream_tls applies to https resources only")
		}
	default:
		return status.Errorf(codes.InvalidArgument, "private resource %s is not http or https; a tcp stream carries nothing a rule can act on", matcher.GetPrivateResourceId())
	}
	return nil
}

// syncPrivateResourceMediation converges the referenced resource's mediation
// with whether any rule still names it. Best-effort: the Networks service
// re-derives mediation every reconciliation pass, so a failed call heals
// without operator action.
func (s *Server) syncPrivateResourceMediation(ctx context.Context, resourceID uuid.UUID) {
	if s.networksClient == nil {
		return
	}
	count, _, err := s.store.CountRulesReferencingPrivateResource(ctx, resourceID)
	if err != nil {
		log.Printf("count rules referencing private resource %s failed: %v", resourceID, err)
		return
	}
	mediation := networksv1.PrivateResourceMediation_PRIVATE_RESOURCE_MEDIATION_TUNNEL
	if count > 0 {
		mediation = networksv1.PrivateResourceMediation_PRIVATE_RESOURCE_MEDIATION_EGRESS_GATEWAY
	}
	if _, err := s.networksClient.SetPrivateResourceMediation(ctx, &networksv1.SetPrivateResourceMediationRequest{Id: resourceID.String(), Mediation: mediation}); err != nil {
		log.Printf("set mediation for private resource %s failed: %v", resourceID, err)
	}
}

// privateResourceInfos denormalizes the referenced resources' intercept_host
// and protocol into the gateway lookup response, so the gateway needs no
// Networks call on its request path. A resource that cannot be resolved is
// omitted; the gateway refuses its connections rather than guessing.
func (s *Server) privateResourceInfos(ctx context.Context, rules []store.Rule) map[string]*egressv1.PrivateResourceInfo {
	if s.networksClient == nil {
		return nil
	}
	infos := map[string]*egressv1.PrivateResourceInfo{}
	for _, rule := range rules {
		resourceID := rule.Matcher.GetPrivateResourceId()
		if resourceID == "" {
			continue
		}
		if _, done := infos[resourceID]; done {
			continue
		}
		response, err := s.networksClient.GetPrivateResource(ctx, &networksv1.GetPrivateResourceRequest{Id: resourceID})
		if err != nil {
			log.Printf("resolve private resource %s for rule lookup failed: %v", resourceID, err)
			continue
		}
		protocol := egressv1.EgressPrivateResourceProtocol_EGRESS_PRIVATE_RESOURCE_PROTOCOL_UNSPECIFIED
		switch response.GetPrivateResource().GetProtocol() {
		case networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_HTTP:
			protocol = egressv1.EgressPrivateResourceProtocol_EGRESS_PRIVATE_RESOURCE_PROTOCOL_HTTP
		case networksv1.PrivateResourceProtocol_PRIVATE_RESOURCE_PROTOCOL_HTTPS:
			protocol = egressv1.EgressPrivateResourceProtocol_EGRESS_PRIVATE_RESOURCE_PROTOCOL_HTTPS
		}
		infos[resourceID] = &egressv1.PrivateResourceInfo{
			InterceptHost: response.GetPrivateResource().GetInterceptHost(),
			Protocol:      protocol,
		}
	}
	if len(infos) == 0 {
		return nil
	}
	return infos
}

// rejectInterceptCollision fast-fails an attachment that would make the
// target's dials ambiguous. Best-effort by design: group and environment
// writes reach the same state without passing through here, and detection is
// what holds -- an unreachable peer skips the check rather than blocking.
func (s *Server) rejectInterceptCollision(ctx context.Context, rule store.Rule, target attachmentTarget) error {
	if s.networksClient == nil {
		return nil
	}
	if rule.IsPrivateTarget() {
		return s.rejectPrivateAttachmentCollision(ctx, rule, target)
	}
	request := &networksv1.ListPrivateResourcesReachableByRequest{}
	switch target.kind {
	case targetKindAgent:
		request.Principal = &networksv1.ListPrivateResourcesReachableByRequest_AgentId{AgentId: target.id.String()}
	case targetKindEnvironment:
		request.Principal = &networksv1.ListPrivateResourcesReachableByRequest_EnvironmentId{EnvironmentId: target.id.String()}
	default:
		return nil
	}
	response, err := s.networksClient.ListPrivateResourcesReachableBy(ctx, request)
	if err != nil {
		log.Printf("list private resources reachable by %s %s failed: %v", target.kind, target.id, err)
		return nil
	}
	for _, resource := range response.GetPrivateResources() {
		if domainPatternMatchesHost(rule.Matcher.GetDomainPattern(), resource.GetInterceptHost()) && portsOverlap(rule.Matcher.GetPorts(), resource.GetInterceptPorts()) {
			return status.Errorf(codes.FailedPrecondition, "the target already reaches private resource %s intercepting %s; use a rule with that resource as its destination instead", resource.GetId(), resource.GetInterceptHost())
		}
	}
	return nil
}

// The private-target direction of the same collision: attaching this rule
// grants the resource, so a public rule for the resource's hostname already
// reaching the target is the identical ambiguity.
func (s *Server) rejectPrivateAttachmentCollision(ctx context.Context, rule store.Rule, target attachmentTarget) error {
	resourceID := rule.Matcher.GetPrivateResourceId()
	response, err := s.networksClient.GetPrivateResource(forwardCallerIdentity(ctx), &networksv1.GetPrivateResourceRequest{Id: resourceID})
	if err != nil {
		log.Printf("resolve private resource %s for attach collision check failed: %v", resourceID, err)
		return nil
	}
	resource := response.GetPrivateResource()
	var attached []store.Rule
	switch target.kind {
	case targetKindAgent:
		attached, err = s.store.ListRulesByAgent(ctx, target.id)
	case targetKindEnvironment:
		attached, err = s.store.ListRulesByEnvironment(ctx, target.id)
	default:
		return nil
	}
	if err != nil {
		log.Printf("list rules attached to %s %s failed: %v", target.kind, target.id, err)
		return nil
	}
	for _, other := range attached {
		if other.IsPrivateTarget() {
			continue
		}
		if domainPatternMatchesHost(other.Matcher.GetDomainPattern(), resource.GetInterceptHost()) && portsOverlap(other.Matcher.GetPorts(), resource.GetInterceptPorts()) {
			return status.Errorf(codes.FailedPrecondition, "egress rule %s already intercepts %s for this target", other.ID, resource.GetInterceptHost())
		}
	}
	return nil
}

// Matches the sidecar's interception semantics: exact hostname or a
// single-label "*." wildcard.
func domainPatternMatchesHost(pattern string, host string) bool {
	if pattern == "" || host == "" {
		return false
	}
	if rest, ok := strings.CutPrefix(pattern, "*."); ok {
		label, remainder, found := strings.Cut(host, ".")
		return found && label != "" && remainder == rest
	}
	return pattern == host
}

func portsOverlap(rulePorts []int32, interceptPorts []int32) bool {
	for _, rulePort := range rulePorts {
		for _, interceptPort := range interceptPorts {
			if rulePort == interceptPort {
				return true
			}
		}
	}
	return false
}
