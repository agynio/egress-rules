-- Rules are not unique per destination: several rules on one domain or one
-- private resource, attached to different targets, is how each target gets
-- its own credential.
DROP INDEX IF EXISTS egress_rules_organization_domain_pattern_uidx;

-- TLS settings for the gateway->target leg of a private https destination.
ALTER TABLE egress_rules ADD COLUMN IF NOT EXISTS upstream_tls JSONB;
