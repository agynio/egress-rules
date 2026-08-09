package server

import (
	"fmt"
	"net"
	"sort"
	"strings"

	egressv1 "github.com/agynio/egress/.gen/go/agynio/api/egress/v1"
	"github.com/google/uuid"
)

var serviceDefaultPorts = []int32{80, 443}

type validatedRuleInput struct {
	OrganizationID uuid.UUID
	Name           string
	Description    string
	Matcher        *egressv1.EgressRuleMatcher
	Effect         *egressv1.EgressRuleEffect
	SecretIDs      []uuid.UUID
}

func validateRuleInput(organizationIDValue string, name string, description string, matcher *egressv1.EgressRuleMatcher, effect *egressv1.EgressRuleEffect) (validatedRuleInput, error) {
	if isNoopEffect(effect) {
		return validatedRuleInput{}, fmt.Errorf("effect must set deny, allow, or injected headers")
	}
	organizationID, err := uuid.Parse(strings.TrimSpace(organizationIDValue))
	if err != nil {
		return validatedRuleInput{}, fmt.Errorf("organization_id: invalid uuid")
	}
	validatedMatcher, err := validateMatcher(matcher)
	if err != nil {
		return validatedRuleInput{}, err
	}
	validatedEffect, secretIDs, err := validateEffect(effect)
	if err != nil {
		return validatedRuleInput{}, err
	}
	return validatedRuleInput{
		OrganizationID: organizationID,
		Name:           strings.TrimSpace(name),
		Description:    strings.TrimSpace(description),
		Matcher:        validatedMatcher,
		Effect:         validatedEffect,
		SecretIDs:      secretIDs,
	}, nil
}

func validateMatcher(matcher *egressv1.EgressRuleMatcher) (*egressv1.EgressRuleMatcher, error) {
	if matcher == nil {
		return nil, fmt.Errorf("matcher is required")
	}
	domainPattern := strings.ToLower(strings.TrimSpace(matcher.GetDomainPattern()))
	if domainPattern == "" {
		return nil, fmt.Errorf("matcher.domain_pattern is required")
	}
	if err := rejectReservedDomainPattern(domainPattern); err != nil {
		return nil, err
	}
	ports, err := validatePorts(matcher.GetPorts())
	if err != nil {
		return nil, err
	}
	methods, err := validateMethods(matcher.GetMethods())
	if err != nil {
		return nil, err
	}
	return &egressv1.EgressRuleMatcher{
		DomainPattern: domainPattern,
		Ports:         ports,
		Methods:       methods,
		PathPattern:   strings.TrimSpace(matcher.GetPathPattern()),
	}, nil
}

func rejectReservedDomainPattern(domainPattern string) error {
	reservedSuffixes := []string{".agyn", ".svc", ".cluster.local"}
	trimmedWildcard := strings.TrimPrefix(domainPattern, "*.")
	for _, suffix := range reservedSuffixes {
		if trimmedWildcard == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(trimmedWildcard, suffix) {
			return fmt.Errorf("matcher.domain_pattern uses reserved suffix %s", suffix)
		}
	}
	if overlapsCarrierGradeNAT(domainPattern) {
		return fmt.Errorf("matcher.domain_pattern overlaps reserved CIDR 100.64.0.0/10")
	}
	return nil
}

func overlapsCarrierGradeNAT(value string) bool {
	_, reserved, err := net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		panic(err)
	}
	if ip := net.ParseIP(value); ip != nil {
		return reserved.Contains(ip)
	}
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return false
	}
	return cidrOverlap(network, reserved)
}

func cidrOverlap(a *net.IPNet, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

func validatePorts(input []int32) ([]int32, error) {
	ports := append([]int32(nil), input...)
	if len(ports) == 0 {
		ports = append([]int32(nil), serviceDefaultPorts...)
	}
	seen := map[int32]struct{}{}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("matcher.ports contains invalid port %d", port)
		}
		seen[port] = struct{}{}
	}
	ports = ports[:0]
	for port := range seen {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports, nil
}

func validateMethods(input []string) ([]string, error) {
	methods := make([]string, 0, len(input))
	seen := map[string]struct{}{}
	for _, raw := range input {
		method := strings.ToUpper(strings.TrimSpace(raw))
		if method == "" {
			return nil, fmt.Errorf("matcher.methods contains empty method")
		}
		if _, ok := seen[method]; ok {
			continue
		}
		seen[method] = struct{}{}
		methods = append(methods, method)
	}
	sort.Strings(methods)
	return methods, nil
}

func validateEffect(effect *egressv1.EgressRuleEffect) (*egressv1.EgressRuleEffect, []uuid.UUID, error) {
	if effect == nil {
		return &egressv1.EgressRuleEffect{}, nil, nil
	}
	validated := &egressv1.EgressRuleEffect{
		Inject: make([]*egressv1.EgressRuleHeader, 0, len(effect.GetInject())),
	}
	if effect.Action != nil {
		action := effect.GetAction()
		if action != egressv1.EgressRuleAction_EGRESS_RULE_ACTION_ALLOW && action != egressv1.EgressRuleAction_EGRESS_RULE_ACTION_DENY {
			return nil, nil, fmt.Errorf("effect.action is invalid")
		}
		validated.Action = action.Enum()
	}
	secretIDs := make([]uuid.UUID, 0)
	seenHeaders := map[string]struct{}{}
	for index, header := range effect.GetInject() {
		validatedHeader, secretID, err := validateHeader(header, index)
		if err != nil {
			return nil, nil, err
		}
		lowerName := strings.ToLower(validatedHeader.GetName())
		if _, exists := seenHeaders[lowerName]; exists {
			return nil, nil, fmt.Errorf("effect.inject[%d].name duplicates another injected header", index)
		}
		seenHeaders[lowerName] = struct{}{}
		if secretID != nil {
			secretIDs = append(secretIDs, *secretID)
		}
		validated.Inject = append(validated.Inject, validatedHeader)
	}
	return validated, secretIDs, nil
}

func validateHeader(header *egressv1.EgressRuleHeader, index int) (*egressv1.EgressRuleHeader, *uuid.UUID, error) {
	if header == nil {
		return nil, nil, fmt.Errorf("effect.inject[%d] is required", index)
	}
	name := strings.TrimSpace(header.GetName())
	if name == "" {
		return nil, nil, fmt.Errorf("effect.inject[%d].name is required", index)
	}
	if strings.ContainsAny(name, "\r\n:") {
		return nil, nil, fmt.Errorf("effect.inject[%d].name is invalid", index)
	}
	scheme := header.GetScheme()
	if scheme != egressv1.HeaderAuthScheme_HEADER_AUTH_SCHEME_UNSPECIFIED && scheme != egressv1.HeaderAuthScheme_HEADER_AUTH_SCHEME_BEARER && scheme != egressv1.HeaderAuthScheme_HEADER_AUTH_SCHEME_BASIC {
		return nil, nil, fmt.Errorf("effect.inject[%d].scheme is invalid", index)
	}
	switch credential := header.GetCredential().(type) {
	case *egressv1.EgressRuleHeader_Value:
		value := strings.TrimSpace(credential.Value)
		if value == "" {
			return nil, nil, fmt.Errorf("effect.inject[%d].value is required", index)
		}
		return &egressv1.EgressRuleHeader{Name: name, Scheme: scheme, Credential: &egressv1.EgressRuleHeader_Value{Value: value}}, nil, nil
	case *egressv1.EgressRuleHeader_SecretId:
		secretID, err := uuid.Parse(strings.TrimSpace(credential.SecretId))
		if err != nil {
			return nil, nil, fmt.Errorf("effect.inject[%d].secret_id is invalid", index)
		}
		return &egressv1.EgressRuleHeader{Name: name, Scheme: scheme, Credential: &egressv1.EgressRuleHeader_SecretId{SecretId: secretID.String()}}, &secretID, nil
	default:
		return nil, nil, fmt.Errorf("effect.inject[%d] must set value or secret_id", index)
	}
}

func isNoopEffect(effect *egressv1.EgressRuleEffect) bool {
	if effect == nil {
		return true
	}
	if effect.GetAction() == egressv1.EgressRuleAction_EGRESS_RULE_ACTION_ALLOW || effect.GetAction() == egressv1.EgressRuleAction_EGRESS_RULE_ACTION_DENY {
		return false
	}
	return len(effect.GetInject()) == 0
}
