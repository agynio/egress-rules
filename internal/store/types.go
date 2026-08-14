package store

import (
	"encoding/base64"
	"fmt"
	"time"

	egressv1 "github.com/agynio/egress/.gen/go/agynio/api/egress/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultListPageSize int32 = 50
	maxListPageSize     int32 = 100
)

// Rule is the persisted egress rule model.
type Rule struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	Name           string
	Description    string
	Matcher        *egressv1.EgressRuleMatcher
	Effect         *egressv1.EgressRuleEffect
	// Private https targets only; nil otherwise.
	UpstreamTLS       *egressv1.EgressRuleUpstreamTls
	OpenZitiServiceID string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// IsPrivateTarget reports whether the rule names a private resource rather
// than a public domain pattern.
func (r Rule) IsPrivateTarget() bool {
	return r.Matcher.GetPrivateResourceId() != ""
}

// Attachment is the persisted egress rule attachment model.
// Attachment targets exactly one of an agent or an environment; the other id
// is nil.
type Attachment struct {
	ID                   uuid.UUID
	RuleID               uuid.UUID
	AgentID              *uuid.UUID
	EnvironmentID        *uuid.UUID
	OpenZitiDialPolicyID string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// RuleListResult contains paginated rules.
type RuleListResult struct {
	Rules      []Rule
	NextCursor *PageCursor
}

// AttachmentListResult contains paginated attachments.
type AttachmentListResult struct {
	Attachments []Attachment
	NextCursor  *PageCursor
}

// PageCursor is an id-based pagination cursor.
type PageCursor struct {
	AfterID uuid.UUID
}

func NormalizePageSize(size int32) int32 {
	if size <= 0 {
		return defaultListPageSize
	}
	if size > maxListPageSize {
		return maxListPageSize
	}
	return size
}

func EncodePageCursor(cursor *PageCursor) string {
	if cursor == nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(cursor.AfterID.String()))
}

func DecodePageCursor(token string) (*PageCursor, error) {
	if token == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("invalid page_token")
	}
	id, err := uuid.Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid page_token")
	}
	return &PageCursor{AfterID: id}, nil
}

func RuleToProto(rule Rule) *egressv1.EgressRule {
	return &egressv1.EgressRule{
		Meta: &egressv1.EntityMeta{
			Id:        rule.ID.String(),
			CreatedAt: timestamppb.New(rule.CreatedAt),
			UpdatedAt: timestamppb.New(rule.UpdatedAt),
		},
		OrganizationId: rule.OrganizationID.String(),
		Name:           rule.Name,
		Description:    rule.Description,
		Matcher:        rule.Matcher,
		Effect:         rule.Effect,
		UpstreamTls:    rule.UpstreamTLS,
	}
}

func AttachmentToProto(attachment Attachment) *egressv1.EgressRuleAttachment {
	proto := &egressv1.EgressRuleAttachment{
		Meta: &egressv1.EntityMeta{
			Id:        attachment.ID.String(),
			CreatedAt: timestamppb.New(attachment.CreatedAt),
			UpdatedAt: timestamppb.New(attachment.UpdatedAt),
		},
		RuleId: attachment.RuleID.String(),
	}
	if attachment.EnvironmentID != nil {
		proto.Target = &egressv1.EgressRuleAttachment_EnvironmentId{EnvironmentId: attachment.EnvironmentID.String()}
		return proto
	}
	if attachment.AgentID != nil {
		// agent_id stays populated for a client reading the deprecated field.
		proto.AgentId = attachment.AgentID.String()
		proto.Target = &egressv1.EgressRuleAttachment_AgentTargetId{AgentTargetId: attachment.AgentID.String()}
	}
	return proto
}

// TargetKind filters rules by destination kind in list queries.
type TargetKind int

const (
	TargetKindAny TargetKind = iota
	TargetKindPublic
	TargetKindPrivate
)

// RuleListFilter narrows ListRules beyond the organization.
type RuleListFilter struct {
	PrivateResourceID *uuid.UUID
	TargetKind        TargetKind
}
