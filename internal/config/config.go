package config

import (
	"fmt"
	"os"
	"time"
)

const (
	defaultGRPCAddress          = ":50051"
	defaultZitiManagementTarget = "ziti-management:50051"
	defaultAuthorizationTarget  = "authorization:50051"
	defaultSecretsTarget        = "secrets:50051"
	defaultNotificationsTarget  = "notifications:50051"
	defaultNetworksTarget       = "networks:50051"
	defaultAgentsTarget         = "agents:50051"
	defaultReconcileInterval    = time.Minute
)

// Config contains runtime configuration for the egress rules service.
type Config struct {
	DatabaseURL            string
	GRPCAddress            string
	ZitiManagementAddress  string
	AuthorizationAddress   string
	SecretsAddress         string
	NotificationsAddress   string
	NetworksAddress        string
	AgentsAddress          string
	ReconciliationInterval time.Duration
}

// Load reads configuration from the process environment.
func Load() (Config, error) {
	cfg := Config{
		DatabaseURL:            os.Getenv("DATABASE_URL"),
		GRPCAddress:            envOrDefault("GRPC_ADDRESS", defaultGRPCAddress),
		ZitiManagementAddress:  envOrDefault("ZITI_MANAGEMENT_ADDRESS", defaultZitiManagementTarget),
		AuthorizationAddress:   envOrDefault("AUTHORIZATION_SERVICE_ADDRESS", defaultAuthorizationTarget),
		SecretsAddress:         envOrDefault("SECRETS_SERVICE_ADDRESS", defaultSecretsTarget),
		NotificationsAddress:   envOrDefault("NOTIFICATIONS_ADDRESS", defaultNotificationsTarget),
		NetworksAddress:        envOrDefault("NETWORKS_SERVICE_ADDRESS", defaultNetworksTarget),
		AgentsAddress:          envOrDefault("AGENTS_SERVICE_ADDRESS", defaultAgentsTarget),
		ReconciliationInterval: defaultReconcileInterval,
	}
	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	if raw := os.Getenv("RECONCILIATION_INTERVAL"); raw != "" {
		interval, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse RECONCILIATION_INTERVAL: %w", err)
		}
		cfg.ReconciliationInterval = interval
	}
	return cfg, nil
}

func envOrDefault(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
