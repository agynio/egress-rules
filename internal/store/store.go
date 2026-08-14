package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	egressv1 "github.com/agynio/egress/.gen/go/agynio/api/egress/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	ruleColumns       = `id, organization_id, name, description, matcher, effect, upstream_tls, openziti_service_id, created_at, updated_at`
	attachmentColumns = `id, rule_id, agent_id, environment_id, openziti_dial_policy_id, created_at, updated_at`
)

// Store persists egress rules and attachments.
type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) CreateRule(ctx context.Context, rule Rule) error {
	matcherJSON, err := protojson.Marshal(rule.Matcher)
	if err != nil {
		return fmt.Errorf("marshal matcher: %w", err)
	}
	effectJSON, err := protojson.Marshal(rule.Effect)
	if err != nil {
		return fmt.Errorf("marshal effect: %w", err)
	}
	upstreamTLSJSON, err := marshalUpstreamTLS(rule.UpstreamTLS)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO egress_rules (id, organization_id, name, description, matcher, effect, upstream_tls, openziti_service_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		rule.ID,
		rule.OrganizationID,
		rule.Name,
		rule.Description,
		matcherJSON,
		effectJSON,
		upstreamTLSJSON,
		rule.OpenZitiServiceID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrRuleAlreadyExists
		}
		return fmt.Errorf("create egress rule: %w", err)
	}
	return nil
}

func (s *Store) UpdateRule(ctx context.Context, rule Rule) error {
	matcherJSON, err := protojson.Marshal(rule.Matcher)
	if err != nil {
		return fmt.Errorf("marshal matcher: %w", err)
	}
	effectJSON, err := protojson.Marshal(rule.Effect)
	if err != nil {
		return fmt.Errorf("marshal effect: %w", err)
	}
	upstreamTLSJSON, err := marshalUpstreamTLS(rule.UpstreamTLS)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE egress_rules
		SET name = $2, description = $3, matcher = $4, effect = $5, upstream_tls = $6, openziti_service_id = $7, updated_at = NOW()
		WHERE id = $1`,
		rule.ID,
		rule.Name,
		rule.Description,
		matcherJSON,
		effectJSON,
		upstreamTLSJSON,
		rule.OpenZitiServiceID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrRuleAlreadyExists
		}
		return fmt.Errorf("update egress rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrRuleNotFound
	}
	return nil
}

func (s *Store) UpdateRuleServiceID(ctx context.Context, id uuid.UUID, serviceID string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE egress_rules SET openziti_service_id = $2, updated_at = NOW() WHERE id = $1`, id, serviceID)
	if err != nil {
		return fmt.Errorf("update egress rule service id: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrRuleNotFound
	}
	return nil
}

func (s *Store) GetRule(ctx context.Context, id uuid.UUID) (Rule, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT %s FROM egress_rules WHERE id = $1`, ruleColumns), id)
	return scanRule(row)
}

func (s *Store) ListRules(ctx context.Context, organizationID uuid.UUID, filter RuleListFilter, pageSize int32, cursor *PageCursor) (RuleListResult, error) {
	limit := NormalizePageSize(pageSize)
	args := []any{organizationID}
	query := fmt.Sprintf(`SELECT %s FROM egress_rules WHERE organization_id = $1`, ruleColumns)
	if filter.PrivateResourceID != nil {
		args = append(args, filter.PrivateResourceID.String())
		query += fmt.Sprintf(" AND %s = $%d", matcherPrivateResourceIDExpr, len(args))
	}
	switch filter.TargetKind {
	case TargetKindPublic:
		query += fmt.Sprintf(" AND %s IS NULL", matcherPrivateResourceIDExpr)
	case TargetKindPrivate:
		query += fmt.Sprintf(" AND %s IS NOT NULL", matcherPrivateResourceIDExpr)
	}
	if cursor != nil {
		args = append(args, cursor.AfterID)
		query += fmt.Sprintf(" AND id > $%d", len(args))
	}
	args = append(args, limit+1)
	query += fmt.Sprintf(" ORDER BY id ASC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return RuleListResult{}, fmt.Errorf("list egress rules: %w", err)
	}
	defer rows.Close()

	rules, err := collectRules(rows)
	if err != nil {
		return RuleListResult{}, fmt.Errorf("list egress rules: %w", err)
	}
	result := RuleListResult{Rules: rules}
	if int32(len(result.Rules)) > limit {
		nextID := result.Rules[limit-1].ID
		result.Rules = result.Rules[:limit]
		result.NextCursor = &PageCursor{AfterID: nextID}
	}
	return result, nil
}

func (s *Store) ListAllRules(ctx context.Context) ([]Rule, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`SELECT %s FROM egress_rules ORDER BY id ASC`, ruleColumns))
	if err != nil {
		return nil, fmt.Errorf("list all egress rules: %w", err)
	}
	defer rows.Close()
	rules, err := collectRules(rows)
	if err != nil {
		return nil, fmt.Errorf("list all egress rules: %w", err)
	}
	return rules, nil
}

func (s *Store) ListRulesByEnvironment(ctx context.Context, environmentID uuid.UUID) ([]Rule, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s
		FROM egress_rules r
		JOIN egress_rule_attachments a ON a.rule_id = r.id
		WHERE a.environment_id = $1
		ORDER BY r.id ASC`, prefixedRuleColumns("r")), environmentID)
	if err != nil {
		return nil, fmt.Errorf("list egress rules by environment: %w", err)
	}
	defer rows.Close()
	rules, err := collectRules(rows)
	if err != nil {
		return nil, fmt.Errorf("list egress rules by environment: %w", err)
	}
	return rules, nil
}

func (s *Store) ListRulesByAgent(ctx context.Context, agentID uuid.UUID) ([]Rule, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s
		FROM egress_rules r
		JOIN egress_rule_attachments a ON a.rule_id = r.id
		WHERE a.agent_id = $1
		ORDER BY r.id ASC`, prefixedRuleColumns("r")), agentID)
	if err != nil {
		return nil, fmt.Errorf("list egress rules by agent: %w", err)
	}
	defer rows.Close()
	rules, err := collectRules(rows)
	if err != nil {
		return nil, fmt.Errorf("list egress rules by agent: %w", err)
	}
	return rules, nil
}

func (s *Store) DeleteRule(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM egress_rules WHERE id = $1`, id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return ErrRuleHasAttachments
		}
		return fmt.Errorf("delete egress rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrRuleNotFound
	}
	return nil
}

func (s *Store) CountAttachmentsByRule(ctx context.Context, ruleID uuid.UUID) (int32, error) {
	var count int32
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM egress_rule_attachments WHERE rule_id = $1`, ruleID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count egress rule attachments: %w", err)
	}
	return count, nil
}

func (s *Store) CreateAttachment(ctx context.Context, attachment Attachment) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO egress_rule_attachments (id, rule_id, agent_id, environment_id, openziti_dial_policy_id)
		VALUES ($1, $2, $3, $4, $5)`,
		attachment.ID,
		attachment.RuleID,
		attachment.AgentID,
		attachment.EnvironmentID,
		attachment.OpenZitiDialPolicyID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrAttachmentExists
		}
		return fmt.Errorf("create egress rule attachment: %w", err)
	}
	return nil
}

func (s *Store) UpdateAttachmentPolicyID(ctx context.Context, id uuid.UUID, policyID string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE egress_rule_attachments SET openziti_dial_policy_id = $2, updated_at = NOW() WHERE id = $1`, id, policyID)
	if err != nil {
		return fmt.Errorf("update egress rule attachment policy id: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAttachmentNotFound
	}
	return nil
}

func (s *Store) ListAllAttachments(ctx context.Context) ([]Attachment, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`SELECT %s FROM egress_rule_attachments ORDER BY id ASC`, attachmentColumns))
	if err != nil {
		return nil, fmt.Errorf("list all egress rule attachments: %w", err)
	}
	defer rows.Close()
	attachments, err := collectAttachments(rows)
	if err != nil {
		return nil, fmt.Errorf("list all egress rule attachments: %w", err)
	}
	return attachments, nil
}

func (s *Store) GetAttachment(ctx context.Context, id uuid.UUID) (Attachment, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT %s FROM egress_rule_attachments WHERE id = $1`, attachmentColumns), id)
	return scanAttachment(row)
}

// GetAttachmentByRuleAndTarget finds the attachment binding a rule to one
// target, whichever kind it is.
func (s *Store) GetAttachmentByRuleAndTarget(ctx context.Context, ruleID uuid.UUID, kind string, targetID uuid.UUID) (Attachment, error) {
	column := "agent_id"
	if kind == "environment" {
		column = "environment_id"
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT %s FROM egress_rule_attachments WHERE rule_id = $1 AND %s = $2`, attachmentColumns, column), ruleID, targetID)
	return scanAttachment(row)
}

func (s *Store) GetAttachmentByRuleAndAgent(ctx context.Context, ruleID uuid.UUID, agentID uuid.UUID) (Attachment, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT %s FROM egress_rule_attachments WHERE rule_id = $1 AND agent_id = $2`, attachmentColumns), ruleID, agentID)
	return scanAttachment(row)
}

func (s *Store) ListAttachments(ctx context.Context, organizationID uuid.UUID, ruleID *uuid.UUID, agentID *uuid.UUID, pageSize int32, cursor *PageCursor) (AttachmentListResult, error) {
	limit := NormalizePageSize(pageSize)
	args := []any{organizationID}
	query := fmt.Sprintf(`
		SELECT %s
		FROM egress_rule_attachments a
		JOIN egress_rules r ON r.id = a.rule_id
		WHERE r.organization_id = $1`, prefixedAttachmentColumns("a"))
	if ruleID != nil {
		args = append(args, *ruleID)
		query += fmt.Sprintf(" AND a.rule_id = $%d", len(args))
	}
	if agentID != nil {
		args = append(args, *agentID)
		query += fmt.Sprintf(" AND a.agent_id = $%d", len(args))
	}
	if cursor != nil {
		args = append(args, cursor.AfterID)
		query += fmt.Sprintf(" AND a.id > $%d", len(args))
	}
	args = append(args, limit+1)
	query += fmt.Sprintf(" ORDER BY a.id ASC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return AttachmentListResult{}, fmt.Errorf("list egress rule attachments: %w", err)
	}
	defer rows.Close()
	attachments, err := collectAttachments(rows)
	if err != nil {
		return AttachmentListResult{}, fmt.Errorf("list egress rule attachments: %w", err)
	}
	result := AttachmentListResult{Attachments: attachments}
	if int32(len(result.Attachments)) > limit {
		nextID := result.Attachments[limit-1].ID
		result.Attachments = result.Attachments[:limit]
		result.NextCursor = &PageCursor{AfterID: nextID}
	}
	return result, nil
}

func (s *Store) DeleteAttachment(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM egress_rule_attachments WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete egress rule attachment: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAttachmentNotFound
	}
	return nil
}

func (s *Store) CountRulesReferencingSecret(ctx context.Context, secretID uuid.UUID) (int32, []uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id FROM egress_rules
		WHERE EXISTS (
			SELECT 1 FROM jsonb_array_elements(effect->'inject') header
			WHERE header->>'secretId' = $1 OR header->>'secret_id' = $1
		)
		OR upstream_tls->>'caBundleSecretId' = $1
		OR upstream_tls->>'ca_bundle_secret_id' = $1
		ORDER BY id ASC`, secretID.String())
	if err != nil {
		return 0, nil, fmt.Errorf("count egress rules referencing secret: %w", err)
	}
	defer rows.Close()
	ids := make([]uuid.UUID, 0)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return 0, nil, fmt.Errorf("scan egress rule id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, fmt.Errorf("count egress rules referencing secret: %w", err)
	}
	return int32(len(ids)), ids, nil
}

// protojson wrote camelCase historically; both spellings are checked the way
// CountRulesReferencingSecret already does.
const matcherPrivateResourceIDExpr = `COALESCE(matcher->>'privateResourceId', matcher->>'private_resource_id')`

func (s *Store) CountRulesReferencingPrivateResource(ctx context.Context, resourceID uuid.UUID) (int32, []uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`SELECT id FROM egress_rules WHERE %s = $1 ORDER BY id ASC`, matcherPrivateResourceIDExpr), resourceID.String())
	if err != nil {
		return 0, nil, fmt.Errorf("count egress rules referencing private resource: %w", err)
	}
	defer rows.Close()
	ids := make([]uuid.UUID, 0)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return 0, nil, fmt.Errorf("scan egress rule id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, fmt.Errorf("count egress rules referencing private resource: %w", err)
	}
	return int32(len(ids)), ids, nil
}

func (s *Store) ListMediatedPrivateResourceIDs(ctx context.Context, organizationID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT DISTINCT %s FROM egress_rules
		WHERE organization_id = $1 AND %s IS NOT NULL
		ORDER BY 1`, matcherPrivateResourceIDExpr, matcherPrivateResourceIDExpr), organizationID)
	if err != nil {
		return nil, fmt.Errorf("list mediated private resources: %w", err)
	}
	defer rows.Close()
	ids := make([]uuid.UUID, 0)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan private resource id: %w", err)
		}
		id, err := uuid.Parse(raw)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list mediated private resources: %w", err)
	}
	return ids, nil
}

func scanRule(row pgx.Row) (Rule, error) {
	var rule Rule
	var matcherJSON []byte
	var effectJSON []byte
	var upstreamTLSJSON []byte
	if err := row.Scan(
		&rule.ID,
		&rule.OrganizationID,
		&rule.Name,
		&rule.Description,
		&matcherJSON,
		&effectJSON,
		&upstreamTLSJSON,
		&rule.OpenZitiServiceID,
		&rule.CreatedAt,
		&rule.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Rule{}, ErrRuleNotFound
		}
		return Rule{}, err
	}
	matcher := &egressv1.EgressRuleMatcher{}
	if err := protojson.Unmarshal(matcherJSON, matcher); err != nil {
		return Rule{}, fmt.Errorf("unmarshal matcher: %w", err)
	}
	effect := &egressv1.EgressRuleEffect{}
	if err := protojson.Unmarshal(effectJSON, effect); err != nil {
		return Rule{}, fmt.Errorf("unmarshal effect: %w", err)
	}
	rule.Matcher = matcher
	rule.Effect = effect
	if len(upstreamTLSJSON) > 0 {
		upstreamTLS := &egressv1.EgressRuleUpstreamTls{}
		if err := protojson.Unmarshal(upstreamTLSJSON, upstreamTLS); err != nil {
			return Rule{}, fmt.Errorf("unmarshal upstream_tls: %w", err)
		}
		rule.UpstreamTLS = upstreamTLS
	}
	return rule, nil
}

func marshalUpstreamTLS(upstreamTLS *egressv1.EgressRuleUpstreamTls) ([]byte, error) {
	if upstreamTLS == nil {
		return nil, nil
	}
	data, err := protojson.Marshal(upstreamTLS)
	if err != nil {
		return nil, fmt.Errorf("marshal upstream_tls: %w", err)
	}
	return data, nil
}

func scanAttachment(row pgx.Row) (Attachment, error) {
	var attachment Attachment
	if err := row.Scan(
		&attachment.ID,
		&attachment.RuleID,
		&attachment.AgentID,
		&attachment.EnvironmentID,
		&attachment.OpenZitiDialPolicyID,
		&attachment.CreatedAt,
		&attachment.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Attachment{}, ErrAttachmentNotFound
		}
		return Attachment{}, err
	}
	return attachment, nil
}

func collectRules(rows pgx.Rows) ([]Rule, error) {
	rules := make([]Rule, 0)
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func collectAttachments(rows pgx.Rows) ([]Attachment, error) {
	attachments := make([]Attachment, 0)
	for rows.Next() {
		attachment, err := scanAttachment(rows)
		if err != nil {
			return nil, err
		}
		attachments = append(attachments, attachment)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return attachments, nil
}

func prefixedRuleColumns(prefix string) string {
	return fmt.Sprintf(`%s.id, %s.organization_id, %s.name, %s.description, %s.matcher, %s.effect, %s.openziti_service_id, %s.created_at, %s.updated_at`, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix)
}

// Derived from attachmentColumns rather than repeated: both feed scanAttachment,
// and a column added to one list but not the other selects a different number of
// values than the scan expects.
func prefixedAttachmentColumns(prefix string) string {
	columns := strings.Split(attachmentColumns, ", ")
	for i, column := range columns {
		columns[i] = prefix + "." + column
	}
	return strings.Join(columns, ", ")
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
