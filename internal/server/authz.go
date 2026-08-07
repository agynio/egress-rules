package server

import (
	"context"
	"fmt"

	authorizationv1 "github.com/agynio/egress/.gen/go/agynio/api/authorization/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	identityMetadata = "x-identity-id"

	identityObjectPrefix     = "identity:"
	organizationObjectPrefix = "organization:"
	agentObjectPrefix        = "agent:"
	environmentObjectPrefix  = "environment:"

	organizationMemberRelation       = "member"
	organizationOwnerRelation        = "owner"
	agentCanEditConfigRelation       = "can_edit_config"
	agentCanReadConfigRelation       = "can_read_config"
	agentOrgRelation                 = "org"
	environmentCanEditConfigRelation = "can_edit_config"
	environmentOrgRelation           = "org"
)

func identityFromMetadata(ctx context.Context) (uuid.UUID, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return uuid.UUID{}, fmt.Errorf("metadata missing")
	}
	values := md.Get(identityMetadata)
	if len(values) != 1 {
		return uuid.UUID{}, fmt.Errorf("metadata %s: expected single value, got %d", identityMetadata, len(values))
	}
	id, err := uuid.Parse(values[0])
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("metadata %s: invalid uuid", identityMetadata)
	}
	return id, nil
}

func (s *Server) requireOrgOwner(ctx context.Context, identityID uuid.UUID, organizationID uuid.UUID) error {
	return s.requireRelation(ctx, identityID, organizationOwnerRelation, organizationObject(organizationID))
}

func (s *Server) requireOrgMember(ctx context.Context, identityID uuid.UUID, organizationID uuid.UUID) error {
	return s.requireRelation(ctx, identityID, organizationMemberRelation, organizationObject(organizationID))
}

func (s *Server) requireAgentConfigEdit(ctx context.Context, identityID uuid.UUID, agentID uuid.UUID) error {
	return s.requireRelation(ctx, identityID, agentCanEditConfigRelation, agentObject(agentID))
}

func (s *Server) requireAgentConfigRead(ctx context.Context, identityID uuid.UUID, agentID uuid.UUID) error {
	return s.requireRelation(ctx, identityID, agentCanReadConfigRelation, agentObject(agentID))
}

func (s *Server) requireEnvironmentConfigEdit(ctx context.Context, identityID uuid.UUID, environmentID uuid.UUID) error {
	return s.requireRelation(ctx, identityID, environmentCanEditConfigRelation, environmentObject(environmentID))
}

func (s *Server) requireEnvironmentInOrganization(ctx context.Context, organizationID uuid.UUID, environmentID uuid.UUID) error {
	resp, err := s.authorizationClient.Check(ctx, &authorizationv1.CheckRequest{
		TupleKey: &authorizationv1.TupleKey{
			User:     organizationObject(organizationID),
			Relation: environmentOrgRelation,
			Object:   environmentObject(environmentID),
		},
	})
	if err != nil {
		return status.Errorf(codes.Internal, "authorization check: %v", err)
	}
	if !resp.GetAllowed() {
		return status.Error(codes.PermissionDenied, "environment does not belong to rule organization")
	}
	return nil
}

func (s *Server) requireAgentInOrganization(ctx context.Context, organizationID uuid.UUID, agentID uuid.UUID) error {
	resp, err := s.authorizationClient.Check(ctx, &authorizationv1.CheckRequest{
		TupleKey: &authorizationv1.TupleKey{
			User:     organizationObject(organizationID),
			Relation: agentOrgRelation,
			Object:   agentObject(agentID),
		},
	})
	if err != nil {
		return status.Errorf(codes.Internal, "authorization check: %v", err)
	}
	if !resp.GetAllowed() {
		return status.Error(codes.PermissionDenied, "agent does not belong to rule organization")
	}
	return nil
}

func (s *Server) requireRelation(ctx context.Context, identityID uuid.UUID, relation string, object string) error {
	resp, err := s.authorizationClient.Check(ctx, &authorizationv1.CheckRequest{
		TupleKey: &authorizationv1.TupleKey{
			User:     identityObject(identityID),
			Relation: relation,
			Object:   object,
		},
	})
	if err != nil {
		return status.Errorf(codes.Internal, "authorization check: %v", err)
	}
	if !resp.GetAllowed() {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	return nil
}

func identityObject(id uuid.UUID) string {
	return identityObjectPrefix + id.String()
}

func organizationObject(id uuid.UUID) string {
	return organizationObjectPrefix + id.String()
}

func environmentObject(id uuid.UUID) string {
	return environmentObjectPrefix + id.String()
}

func agentObject(id uuid.UUID) string {
	return agentObjectPrefix + id.String()
}
