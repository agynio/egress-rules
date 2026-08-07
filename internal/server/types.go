package server

import (
	"context"

	authorizationv1 "github.com/agynio/egress/.gen/go/agynio/api/authorization/v1"
	egressv1 "github.com/agynio/egress/.gen/go/agynio/api/egress/v1"
	notificationsv1 "github.com/agynio/egress/.gen/go/agynio/api/notifications/v1"
	secretsv1 "github.com/agynio/egress/.gen/go/agynio/api/secrets/v1"
	zitimanagementv1 "github.com/agynio/egress/.gen/go/agynio/api/ziti_management/v1"
	"github.com/agynio/egress/internal/store"
	"github.com/google/uuid"
	"google.golang.org/grpc"
)

type ruleStore interface {
	CreateRule(context.Context, store.Rule) error
	UpdateRule(context.Context, store.Rule) error
	UpdateRuleServiceID(context.Context, uuid.UUID, string) error
	GetRule(context.Context, uuid.UUID) (store.Rule, error)
	ListRules(context.Context, uuid.UUID, int32, *store.PageCursor) (store.RuleListResult, error)
	ListAllRules(context.Context) ([]store.Rule, error)
	ListRulesByAgent(context.Context, uuid.UUID) ([]store.Rule, error)
	DeleteRule(context.Context, uuid.UUID) error
	CountAttachmentsByRule(context.Context, uuid.UUID) (int32, error)
	CreateAttachment(context.Context, store.Attachment) error
	UpdateAttachmentPolicyID(context.Context, uuid.UUID, string) error
	GetAttachment(context.Context, uuid.UUID) (store.Attachment, error)
	GetAttachmentByRuleAndAgent(context.Context, uuid.UUID, uuid.UUID) (store.Attachment, error)
	GetAttachmentByRuleAndTarget(context.Context, uuid.UUID, string, uuid.UUID) (store.Attachment, error)
	ListAllAttachments(context.Context) ([]store.Attachment, error)
	ListAttachments(context.Context, uuid.UUID, *uuid.UUID, *uuid.UUID, int32, *store.PageCursor) (store.AttachmentListResult, error)
	DeleteAttachment(context.Context, uuid.UUID) error
	CountRulesReferencingSecret(context.Context, uuid.UUID) (int32, []uuid.UUID, error)
}

type authorizationClient interface {
	Check(context.Context, *authorizationv1.CheckRequest, ...grpc.CallOption) (*authorizationv1.CheckResponse, error)
}

type secretsClient interface {
	ResolveSecretExists(context.Context, *secretsv1.ResolveSecretExistsRequest, ...grpc.CallOption) (*secretsv1.ResolveSecretExistsResponse, error)
}

type notificationsClient interface {
	Publish(context.Context, *notificationsv1.PublishRequest, ...grpc.CallOption) (*notificationsv1.PublishResponse, error)
}

type zitiManagementClient interface {
	CreateService(context.Context, *zitimanagementv1.CreateServiceRequest, ...grpc.CallOption) (*zitimanagementv1.CreateServiceResponse, error)
	GetService(context.Context, *zitimanagementv1.GetServiceRequest, ...grpc.CallOption) (*zitimanagementv1.GetServiceResponse, error)
	ListServices(context.Context, *zitimanagementv1.ListServicesRequest, ...grpc.CallOption) (*zitimanagementv1.ListServicesResponse, error)
	UpdateService(context.Context, *zitimanagementv1.UpdateServiceRequest, ...grpc.CallOption) (*zitimanagementv1.UpdateServiceResponse, error)
	DeleteService(context.Context, *zitimanagementv1.DeleteServiceRequest, ...grpc.CallOption) (*zitimanagementv1.DeleteServiceResponse, error)
	CreateServicePolicy(context.Context, *zitimanagementv1.CreateServicePolicyRequest, ...grpc.CallOption) (*zitimanagementv1.CreateServicePolicyResponse, error)
	GetServicePolicy(context.Context, *zitimanagementv1.GetServicePolicyRequest, ...grpc.CallOption) (*zitimanagementv1.GetServicePolicyResponse, error)
	ListServicePolicies(context.Context, *zitimanagementv1.ListServicePoliciesRequest, ...grpc.CallOption) (*zitimanagementv1.ListServicePoliciesResponse, error)
	DeleteServicePolicy(context.Context, *zitimanagementv1.DeleteServicePolicyRequest, ...grpc.CallOption) (*zitimanagementv1.DeleteServicePolicyResponse, error)
}

// Server implements EgressRulesService.
type Server struct {
	egressv1.UnimplementedEgressRulesServiceServer
	store               ruleStore
	authorizationClient authorizationClient
	secretsClient       secretsClient
	notificationsClient notificationsClient
	zitiClient          zitiManagementClient
}

// Options defines dependencies required by Server.
type Options struct {
	Store               ruleStore
	AuthorizationClient authorizationClient
	SecretsClient       secretsClient
	NotificationsClient notificationsClient
	ZitiClient          zitiManagementClient
}

func New(options Options) *Server {
	return &Server{
		store:               options.Store,
		authorizationClient: options.AuthorizationClient,
		secretsClient:       options.SecretsClient,
		notificationsClient: options.NotificationsClient,
		zitiClient:          options.ZitiClient,
	}
}
