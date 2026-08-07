-- An attachment targets exactly one of an agent or an environment. agent_id
-- becomes nullable so an environment attachment can leave it unset; the check
-- keeps every row pointing at one target.
ALTER TABLE egress_rule_attachments
    ADD COLUMN IF NOT EXISTS environment_id UUID;

ALTER TABLE egress_rule_attachments
    ALTER COLUMN agent_id DROP NOT NULL;

ALTER TABLE egress_rule_attachments
    DROP CONSTRAINT IF EXISTS egress_rule_attachments_one_target;

ALTER TABLE egress_rule_attachments
    ADD CONSTRAINT egress_rule_attachments_one_target
    CHECK ((agent_id IS NULL) <> (environment_id IS NULL));

CREATE UNIQUE INDEX IF NOT EXISTS egress_rule_attachments_rule_environment_key
    ON egress_rule_attachments (rule_id, environment_id)
    WHERE environment_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS egress_rule_attachments_environment_id_idx
    ON egress_rule_attachments (environment_id, id)
    WHERE environment_id IS NOT NULL;
