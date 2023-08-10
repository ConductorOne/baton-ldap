package connector

import (
	"context"

	"github.com/conductorone/baton-ldap/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
)

var (
	resourceTypeUser = &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: annotationsForUserResourceType(),
	}
	resourceTypeGroup = &v2.ResourceType{
		Id:          "group",
		DisplayName: "Group",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_GROUP,
		},
	}
	resourceTypeRole = &v2.ResourceType{
		Id:          "role",
		DisplayName: "Role",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_ROLE,
		},
	}
)

type LDAP struct {
	client *ldap.Client
}

func (l *LDAP) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		userBuilder(l.client),
		groupBuilder(l.client),
		roleBuilder(l.client),
	}
}

func (l *LDAP) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "LDAP",
		// TODO: add better description
		Description: "LDAP connector for Baton",
	}, nil
}

// Validates that the user has read access to all relevant tables (more information in the readme).
func (l *LDAP) Validate(ctx context.Context) (annotations.Annotations, error) {
	// TODO: implement validation of user binding
	return nil, nil
}

// New returns the LDAP connector.
func New(ctx context.Context, domain string, baseDN string, password string) (*LDAP, error) {
	conn, err := ldap.TestConnection(domain)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	ldapClient, err := ldap.NewClient(ctx, domain, baseDN, password)
	if err != nil {
		return nil, err
	}

	return &LDAP{
		client: ldapClient,
	}, nil
}
