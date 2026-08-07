package server

import (
	"context"
	"log"
	"strings"
	"time"

	zitimanagementv1 "github.com/agynio/egress/.gen/go/agynio/api/ziti_management/v1"
	"github.com/agynio/egress/internal/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const reconciliationPageSize int32 = 100

type Reconciler struct {
	server   *Server
	interval time.Duration
}

func NewReconciler(server *Server, interval time.Duration) *Reconciler {
	if interval <= 0 {
		panic("reconciliation interval must be positive")
	}
	return &Reconciler{server: server, interval: interval}
}

func (r *Reconciler) Run(ctx context.Context) {
	r.runOnce(ctx)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.runOnce(ctx)
		}
	}
}

func (r *Reconciler) runOnce(ctx context.Context) {
	if err := r.server.Reconcile(ctx); err != nil {
		log.Printf("egress rules reconciliation failed: %v", err)
	}
}

func (s *Server) Reconcile(ctx context.Context) error {
	rules, err := s.store.ListAllRules(ctx)
	if err != nil {
		return toStatusError(err)
	}
	attachments, err := s.store.ListAllAttachments(ctx)
	if err != nil {
		return toStatusError(err)
	}
	ruleServiceIDs := make(map[string]string, len(rules))
	for _, rule := range rules {
		serviceID, err := s.reconcileRuleService(ctx, rule)
		if err != nil {
			return err
		}
		if serviceID != rule.OpenZitiServiceID {
			if err := s.store.UpdateRuleServiceID(ctx, rule.ID, serviceID); err != nil {
				return toStatusError(err)
			}
		}
		ruleServiceIDs[rule.ID.String()] = serviceID
	}
	for _, attachment := range attachments {
		serviceID, ok := ruleServiceIDs[attachment.RuleID.String()]
		if !ok {
			return status.Errorf(codes.Internal, "egress rule attachment %s references unknown rule %s", attachment.ID, attachment.RuleID)
		}
		policyID, err := s.reconcileAttachmentPolicy(ctx, attachment, serviceID)
		if err != nil {
			return err
		}
		if policyID != attachment.OpenZitiDialPolicyID {
			if err := s.store.UpdateAttachmentPolicyID(ctx, attachment.ID, policyID); err != nil {
				return toStatusError(err)
			}
		}
	}
	if err := s.deleteOrphanServices(ctx, rules); err != nil {
		return err
	}
	if err := s.deleteOrphanServicePolicies(ctx, attachments); err != nil {
		return err
	}
	return nil
}

func (s *Server) deleteOrphanServices(ctx context.Context, rules []store.Rule) error {
	managedNames := map[string]struct{}{}
	for _, rule := range rules {
		managedNames[egressServiceName(rule.ID)] = struct{}{}
	}
	pageToken := ""
	for {
		prefix := egressServiceNamePrefix()
		resp, err := s.zitiClient.ListServices(ctx, &zitimanagementv1.ListServicesRequest{
			NamePrefix:     prefix,
			RoleAttributes: []string{egressServiceRoleAttribute},
			PageSize:       reconciliationPageSize,
			PageToken:      pageToken,
		})
		if err != nil {
			return status.Errorf(codes.Internal, "list egress rule services: %v", err)
		}
		for _, service := range resp.GetServices() {
			if _, ok := managedNames[service.GetName()]; ok {
				continue
			}
			if err := s.deleteRuleService(ctx, service.GetZitiServiceId()); err != nil {
				return err
			}
		}
		pageToken = resp.GetNextPageToken()
		if pageToken == "" {
			return nil
		}
	}
}

func (s *Server) deleteOrphanServicePolicies(ctx context.Context, attachments []store.Attachment) error {
	managedNames := map[string]struct{}{}
	for _, attachment := range attachments {
		target, err := targetForAttachment(attachment)
		if err != nil {
			continue
		}
		managedNames[egressDialPolicyName(attachment.RuleID, target)] = struct{}{}
	}
	pageToken := ""
	for {
		prefix := egressServiceNamePrefix()
		resp, err := s.zitiClient.ListServicePolicies(ctx, &zitimanagementv1.ListServicePoliciesRequest{
			NamePrefix: prefix,
			Type:       zitimanagementv1.ServicePolicyType_SERVICE_POLICY_TYPE_DIAL,
			PageSize:   reconciliationPageSize,
			PageToken:  pageToken,
		})
		if err != nil {
			return status.Errorf(codes.Internal, "list egress rule service policies: %v", err)
		}
		for _, policy := range resp.GetServicePolicies() {
			if !strings.HasSuffix(policy.GetName(), "-dial") {
				continue
			}
			if _, ok := managedNames[policy.GetName()]; ok {
				continue
			}
			if err := s.deleteAttachmentPolicy(ctx, policy.GetZitiServicePolicyId()); err != nil {
				return err
			}
		}
		pageToken = resp.GetNextPageToken()
		if pageToken == "" {
			return nil
		}
	}
}

func egressServiceNamePrefix() string {
	return "egress-rule-"
}
