CREATE TABLE IF NOT EXISTS egress_rules (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    matcher JSONB NOT NULL,
    effect JSONB NOT NULL,
    openziti_service_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS egress_rules_organization_id_idx ON egress_rules (organization_id, id);

CREATE TABLE IF NOT EXISTS egress_rule_attachments (
    id UUID PRIMARY KEY,
    rule_id UUID NOT NULL REFERENCES egress_rules(id) ON DELETE RESTRICT,
    agent_id UUID NOT NULL,
    openziti_dial_policy_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (rule_id, agent_id)
);

CREATE INDEX IF NOT EXISTS egress_rule_attachments_agent_id_idx ON egress_rule_attachments (agent_id, id);
CREATE INDEX IF NOT EXISTS egress_rule_attachments_rule_id_idx ON egress_rule_attachments (rule_id, id);
