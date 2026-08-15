package main

import (
	"context"
	"log"
	"net"

	agentsv1 "github.com/agynio/egress/.gen/go/agynio/api/agents/v1"
	authorizationv1 "github.com/agynio/egress/.gen/go/agynio/api/authorization/v1"
	egressv1 "github.com/agynio/egress/.gen/go/agynio/api/egress/v1"
	networksv1 "github.com/agynio/egress/.gen/go/agynio/api/networks/v1"
	notificationsv1 "github.com/agynio/egress/.gen/go/agynio/api/notifications/v1"
	secretsv1 "github.com/agynio/egress/.gen/go/agynio/api/secrets/v1"
	zitimanagementv1 "github.com/agynio/egress/.gen/go/agynio/api/ziti_management/v1"
	"github.com/agynio/egress/internal/config"
	"github.com/agynio/egress/internal/db"
	"github.com/agynio/egress/internal/server"
	"github.com/agynio/egress/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	ctx := context.Background()
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect database: %v", err)
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		log.Fatalf("migrate database: %v", err)
	}

	authzConn := dialService(cfg.AuthorizationAddress)
	defer authzConn.Close()
	secretsConn := dialService(cfg.SecretsAddress)
	defer secretsConn.Close()
	notificationsConn := dialService(cfg.NotificationsAddress)
	defer notificationsConn.Close()
	zitiConn := dialService(cfg.ZitiManagementAddress)
	defer zitiConn.Close()
	networksConn := dialService(cfg.NetworksAddress)
	defer networksConn.Close()
	agentsConn := dialService(cfg.AgentsAddress)
	defer agentsConn.Close()

	grpcServer := grpc.NewServer()
	egressServer := server.New(server.Options{
		Store:               store.New(pool),
		AuthorizationClient: authorizationv1.NewAuthorizationServiceClient(authzConn),
		SecretsClient:       secretsv1.NewSecretsServiceClient(secretsConn),
		NotificationsClient: notificationsv1.NewNotificationsServiceClient(notificationsConn),
		ZitiClient:          zitimanagementv1.NewZitiManagementServiceClient(zitiConn),
		NetworksClient:      networksv1.NewNetworksServiceClient(networksConn),
		AgentsClient:        agentsv1.NewAgentsServiceClient(agentsConn),
	})
	egressv1.RegisterEgressRulesServiceServer(grpcServer, egressServer)
	go server.NewReconciler(egressServer, cfg.ReconciliationInterval).Run(ctx)

	listener, err := net.Listen("tcp", cfg.GRPCAddress)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("egress listening on %s", cfg.GRPCAddress)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("serve grpc: %v", err)
	}
}

func dialService(target string) *grpc.ClientConn {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial %s: %v", target, err)
	}
	return conn
}
