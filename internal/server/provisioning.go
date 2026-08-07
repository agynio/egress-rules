package server

import (
	"context"
	"fmt"
	"strings"

	egressv1 "github.com/agynio/egress/.gen/go/agynio/api/egress/v1"
	zitimanagementv1 "github.com/agynio/egress/.gen/go/agynio/api/ziti_management/v1"
	"github.com/agynio/egress/internal/store"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	egressServiceRoleAttribute = "egress-services"
	tcpProtocol                = "tcp"
	allIPv4Addresses           = "0.0.0.0/0"
	minimumTCPPort             = 1
	maximumTCPPort             = 65535
)

func egressServiceName(ruleID uuid.UUID) string {
	return fmt.Sprintf("egress-rule-%s", ruleID)
}

func egressDialPolicyName(ruleID uuid.UUID, target attachmentTarget) string {
	return fmt.Sprintf("egress-rule-%s-%s-%s-dial", ruleID, target.kind, target.id)
}

func agentRole(agentID uuid.UUID) string {
	return fmt.Sprintf("#agent-%s", agentID)
}

func environmentRole(environmentID uuid.UUID) string {
	return fmt.Sprintf("#environment-%s", environmentID)
}

// attachmentTarget is the one entity an attachment binds a rule to. The
// Orchestrator stamps the matching role attribute on every workload identity it
// creates -- agent workloads and sandboxes alike -- so the dial policy admits
// whatever runs under the target.
type attachmentTarget struct {
	kind string
	id   uuid.UUID
}

func targetForAttachment(attachment store.Attachment) (attachmentTarget, error) {
	switch {
	case attachment.EnvironmentID != nil:
		return attachmentTarget{kind: "environment", id: *attachment.EnvironmentID}, nil
	case attachment.AgentID != nil:
		return attachmentTarget{kind: "agent", id: *attachment.AgentID}, nil
	default:
		return attachmentTarget{}, fmt.Errorf("attachment %s has no target", attachment.ID)
	}
}

func (t attachmentTarget) identityRole() string {
	if t.kind == "environment" {
		return environmentRole(t.id)
	}
	return agentRole(t.id)
}

func zitiServiceIDRole(serviceID string) string {
	return fmt.Sprintf("@%s", serviceID)
}

func (s *Server) provisionRuleService(ctx context.Context, ruleID uuid.UUID, matcher *egressv1.EgressRuleMatcher) (string, error) {
	req := createServiceRequest(ruleID, matcher)
	req.ReturnExisting = true
	resp, err := s.zitiClient.CreateService(ctx, req)
	if err != nil {
		return "", status.Errorf(codes.Internal, "create egress rule service: %v", err)
	}
	serviceID := resp.GetZitiServiceId()
	if serviceID == "" {
		return "", status.Error(codes.Internal, "create egress rule service: missing ziti_service_id")
	}
	return serviceID, nil
}

func (s *Server) reconcileRuleService(ctx context.Context, rule store.Rule) (string, error) {
	serviceID := rule.OpenZitiServiceID
	if serviceID == "" {
		return s.provisionRuleService(ctx, rule.ID, rule.Matcher)
	}
	resp, err := s.zitiClient.GetService(ctx, &zitimanagementv1.GetServiceRequest{ZitiServiceId: serviceID})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return s.provisionRuleService(ctx, rule.ID, rule.Matcher)
		}
		return "", status.Errorf(codes.Internal, "get egress rule service: %v", err)
	}
	if serviceMatchesRule(resp.GetService(), rule) {
		return serviceID, nil
	}
	return s.updateRuleService(ctx, rule)
}

func (s *Server) updateRuleService(ctx context.Context, rule store.Rule) (string, error) {
	serviceID := rule.OpenZitiServiceID
	if serviceID == "" {
		return s.provisionRuleService(ctx, rule.ID, rule.Matcher)
	}
	update, err := s.zitiClient.UpdateService(ctx, &zitimanagementv1.UpdateServiceRequest{
		ZitiServiceId:     serviceID,
		HostV1Config:      hostV1Config(rule.Matcher),
		InterceptV1Config: interceptV1Config(rule.Matcher),
	})
	if err != nil {
		return "", status.Errorf(codes.Internal, "update egress rule service: %v", err)
	}
	updatedID := update.GetService().GetZitiServiceId()
	if updatedID == "" {
		return "", status.Error(codes.Internal, "update egress rule service: missing ziti_service_id")
	}
	return updatedID, nil
}

func (s *Server) deleteRuleService(ctx context.Context, serviceID string) error {
	if serviceID == "" {
		return nil
	}
	_, err := s.zitiClient.DeleteService(ctx, &zitimanagementv1.DeleteServiceRequest{ZitiServiceId: serviceID})
	if err != nil {
		return status.Errorf(codes.Internal, "delete egress rule service: %v", err)
	}
	return nil
}

func (s *Server) provisionAttachmentPolicy(ctx context.Context, ruleID uuid.UUID, target attachmentTarget, serviceID string) (string, error) {
	return s.createAttachmentPolicy(ctx, ruleID, target, serviceID, true)
}

func (s *Server) createAttachmentPolicy(ctx context.Context, ruleID uuid.UUID, target attachmentTarget, serviceID string, returnExisting bool) (string, error) {
	resp, err := s.zitiClient.CreateServicePolicy(ctx, &zitimanagementv1.CreateServicePolicyRequest{
		Type:           zitimanagementv1.ServicePolicyType_SERVICE_POLICY_TYPE_DIAL,
		Name:           egressDialPolicyName(ruleID, target),
		IdentityRoles:  []string{target.identityRole()},
		ServiceRoles:   []string{zitiServiceIDRole(serviceID)},
		ReturnExisting: returnExisting,
	})
	if err != nil {
		return "", status.Errorf(codes.Internal, "create egress rule dial policy: %v", err)
	}
	policyID := resp.GetZitiServicePolicyId()
	if policyID == "" {
		return "", status.Error(codes.Internal, "create egress rule dial policy: missing ziti_service_policy_id")
	}
	return policyID, nil
}

func (s *Server) reconcileAttachmentPolicy(ctx context.Context, attachment store.Attachment, serviceID string) (string, error) {
	target, err := targetForAttachment(attachment)
	if err != nil {
		return "", err
	}
	policyID := attachment.OpenZitiDialPolicyID
	if policyID == "" {
		return s.provisionAttachmentPolicy(ctx, attachment.RuleID, target, serviceID)
	}
	resp, err := s.zitiClient.GetServicePolicy(ctx, &zitimanagementv1.GetServicePolicyRequest{ZitiServicePolicyId: policyID})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return s.provisionAttachmentPolicy(ctx, attachment.RuleID, target, serviceID)
		}
		return "", status.Errorf(codes.Internal, "get egress rule dial policy: %v", err)
	}
	if servicePolicyMatchesAttachment(resp.GetServicePolicy(), attachment, serviceID) {
		return policyID, nil
	}
	return s.replaceAttachmentPolicy(ctx, attachment, serviceID)
}

func (s *Server) replaceAttachmentPolicy(ctx context.Context, attachment store.Attachment, serviceID string) (string, error) {
	if err := s.deleteAttachmentPolicy(ctx, attachment.OpenZitiDialPolicyID); err != nil {
		return "", err
	}
	target, err := targetForAttachment(attachment)
	if err != nil {
		return "", err
	}
	return s.createAttachmentPolicy(ctx, attachment.RuleID, target, serviceID, false)
}

func (s *Server) deleteAttachmentPolicy(ctx context.Context, policyID string) error {
	if policyID == "" {
		return nil
	}
	_, err := s.zitiClient.DeleteServicePolicy(ctx, &zitimanagementv1.DeleteServicePolicyRequest{ZitiServicePolicyId: policyID})
	if err != nil {
		return status.Errorf(codes.Internal, "delete egress rule dial policy: %v", err)
	}
	return nil
}

func createServiceRequest(ruleID uuid.UUID, matcher *egressv1.EgressRuleMatcher) *zitimanagementv1.CreateServiceRequest {
	return &zitimanagementv1.CreateServiceRequest{
		Name:              egressServiceName(ruleID),
		RoleAttributes:    []string{egressServiceRoleAttribute},
		HostV1Config:      hostV1Config(matcher),
		InterceptV1Config: interceptV1Config(matcher),
	}
}

func hostV1Config(matcher *egressv1.EgressRuleMatcher) *zitimanagementv1.HostV1Config {
	return &zitimanagementv1.HostV1Config{
		Protocol:          tcpProtocol,
		ForwardProtocol:   true,
		ForwardAddress:    true,
		ForwardPort:       true,
		AllowedProtocols:  []string{tcpProtocol},
		AllowedAddresses:  []string{allIPv4Addresses},
		AllowedPortRanges: []*zitimanagementv1.PortRange{{Low: minimumTCPPort, High: maximumTCPPort}},
	}
}

func interceptV1Config(matcher *egressv1.EgressRuleMatcher) *zitimanagementv1.InterceptV1Config {
	return &zitimanagementv1.InterceptV1Config{
		Protocols:  []string{tcpProtocol},
		Addresses:  []string{matcher.GetDomainPattern()},
		PortRanges: portRangesFromPorts(matcher.GetPorts()),
	}
}

func serviceMatchesRule(service *zitimanagementv1.OpenZitiService, rule store.Rule) bool {
	if service == nil {
		return false
	}
	return service.GetName() == egressServiceName(rule.ID) &&
		stringSlicesEqual(service.GetRoleAttributes(), []string{egressServiceRoleAttribute})
}

func servicePolicyMatchesAttachment(policy *zitimanagementv1.OpenZitiServicePolicy, attachment store.Attachment, serviceID string) bool {
	if policy == nil {
		return false
	}
	target, err := targetForAttachment(attachment)
	if err != nil {
		return false
	}
	return policy.GetName() == egressDialPolicyName(attachment.RuleID, target) &&
		policy.GetType() == zitimanagementv1.ServicePolicyType_SERVICE_POLICY_TYPE_DIAL &&
		stringSlicesEqual(policy.GetIdentityRoles(), []string{target.identityRole()}) &&
		stringSlicesEqual(policy.GetServiceRoles(), []string{zitiServiceIDRole(serviceID)})
}

func hostV1ConfigsEqual(left *zitimanagementv1.HostV1Config, right *zitimanagementv1.HostV1Config) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.GetProtocol() == right.GetProtocol() &&
		left.GetPort() == right.GetPort() &&
		left.GetForwardProtocol() == right.GetForwardProtocol() &&
		left.GetForwardAddress() == right.GetForwardAddress() &&
		left.GetForwardPort() == right.GetForwardPort() &&
		stringSlicesEqual(left.GetAllowedProtocols(), right.GetAllowedProtocols()) &&
		stringSlicesEqual(left.GetAllowedAddresses(), right.GetAllowedAddresses()) &&
		portRangesEqual(left.GetAllowedPortRanges(), right.GetAllowedPortRanges())
}

func interceptV1ConfigsEqual(left *zitimanagementv1.InterceptV1Config, right *zitimanagementv1.InterceptV1Config) bool {
	if left == nil || right == nil {
		return left == right
	}
	return stringSlicesEqual(left.GetProtocols(), right.GetProtocols()) &&
		stringSlicesEqual(left.GetAddresses(), right.GetAddresses()) &&
		portRangesEqual(left.GetPortRanges(), right.GetPortRanges())
}

func stringSlicesEqual(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func portRangesEqual(left []*zitimanagementv1.PortRange, right []*zitimanagementv1.PortRange) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].GetLow() != right[i].GetLow() || left[i].GetHigh() != right[i].GetHigh() {
			return false
		}
	}
	return true
}

func portRangesFromPorts(ports []int32) []*zitimanagementv1.PortRange {
	ranges := make([]*zitimanagementv1.PortRange, 0, len(ports))
	for _, port := range ports {
		ranges = append(ranges, &zitimanagementv1.PortRange{Low: port, High: port})
	}
	return ranges
}

const (
	targetKindAgent       = "agent"
	targetKindEnvironment = "environment"
)

// attachmentTargetFromRequest reads the one target a create request names. The
// deprecated agent_id is still accepted so an older client keeps working.
func attachmentTargetFromRequest(req *egressv1.CreateEgressRuleAttachmentRequest) (attachmentTarget, error) {
	if environmentID := strings.TrimSpace(req.GetEnvironmentId()); environmentID != "" {
		id, err := parseUUID(environmentID, "environment_id")
		if err != nil {
			return attachmentTarget{}, err
		}
		return attachmentTarget{kind: targetKindEnvironment, id: id}, nil
	}
	agentValue := strings.TrimSpace(req.GetAgentTargetId())
	if agentValue == "" {
		agentValue = strings.TrimSpace(req.GetAgentId())
	}
	if agentValue == "" {
		return attachmentTarget{}, status.Error(codes.InvalidArgument, "one of environment_id or agent_target_id is required")
	}
	id, err := parseUUID(agentValue, "agent_target_id")
	if err != nil {
		return attachmentTarget{}, err
	}
	return attachmentTarget{kind: targetKindAgent, id: id}, nil
}

func (s *Server) requireTargetConfigEdit(ctx context.Context, callerID uuid.UUID, target attachmentTarget) error {
	if target.kind == targetKindEnvironment {
		return s.requireEnvironmentConfigEdit(ctx, callerID, target.id)
	}
	return s.requireAgentConfigEdit(ctx, callerID, target.id)
}

func (s *Server) requireTargetInOrganization(ctx context.Context, organizationID uuid.UUID, target attachmentTarget) error {
	if target.kind == targetKindEnvironment {
		return s.requireEnvironmentInOrganization(ctx, organizationID, target.id)
	}
	return s.requireAgentInOrganization(ctx, organizationID, target.id)
}
