package connector

import (
	"context"
	"fmt"
	"strconv"

	"github.com/conductorone/baton-ldap/pkg/ldap"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

// InetOrgPerson resource structure
// https://datatracker.ietf.org/doc/html/rfc2798
const (
	userFilter = "(objectClass=inetOrgPerson)"

	attrUserUID         = "uid"
	attrUserCommonName  = "cn"
	attrFirstName       = "givenName"
	attrLastName        = "sn"
	attrUserMail        = "mail"
	attrUserDisplayName = "displayName"

	// Microsoft active directory specific attribute.
	attrUserAccountControl = "userAccountControl"
)

type userResourceType struct {
	resourceType *v2.ResourceType
	client       *ldap.Client
}

func (u *userResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return u.resourceType
}

func parseUserNames(user *ldap.Entry) (string, string, string) {
	fullName := user.GetAttributeValue(attrUserCommonName)
	firstName := user.GetAttributeValue(attrFirstName)
	lastName := user.GetAttributeValue(attrLastName)
	displayName := user.GetAttributeValue(attrUserDisplayName)

	if firstName == "" || lastName == "" {
		firstName, lastName = splitFullName(fullName)
	}

	if displayName == "" {
		displayName = fullName
	}

	return firstName, lastName, displayName
}

func parseUserStatus(user *ldap.Entry) (v2.UserTrait_Status_Status, error) {
	userStatus := v2.UserTrait_Status_STATUS_UNSPECIFIED

	// Currently only UserAccountControlFlag from Microsoft is supported
	userAccountControlFlag := user.GetAttributeValue(attrUserAccountControl)
	if userAccountControlFlag != "" {
		userAccountControlFlag, err := strconv.ParseInt(userAccountControlFlag, 10, 64)
		if err != nil {
			return userStatus, err
		}
		// Check if the ACCOUNTDISABLE flag (bit 2) is set
		// https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
		if (userAccountControlFlag & 2) == 0 {
			userStatus = v2.UserTrait_Status_STATUS_ENABLED
		} else {
			userStatus = v2.UserTrait_Status_STATUS_DISABLED
		}
		return userStatus, nil
	}
	return userStatus, nil
}

// Create a new connector resource for an LDAP User.
func userResource(ctx context.Context, user *ldap.Entry) (*v2.Resource, error) {
	firstName, lastName, displayName := parseUserNames(user)
	userId := user.GetAttributeValue(attrUserUID)

	profile := map[string]interface{}{
		"user_id":    userId,
		"first_name": firstName,
		"last_name":  lastName,
		"path":       user.DN,
	}

	userStatus, err := parseUserStatus(user)
	if err != nil {
		return nil, err
	}

	// If the user status is not set, default to enabled
	if userStatus == v2.UserTrait_Status_STATUS_UNSPECIFIED {
		userStatus = v2.UserTrait_Status_STATUS_ENABLED
	}

	userTraitOptions := []rs.UserTraitOption{
		rs.WithEmail(user.GetAttributeValue(attrUserMail), true),
		rs.WithUserProfile(profile),
		rs.WithStatus(userStatus),
	}

	// if no display name, use the user id
	if displayName == "" {
		displayName = userId
	}

	resource, err := rs.NewUserResource(
		displayName,
		resourceTypeUser,
		user.DN,
		userTraitOptions,
	)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

func (u *userResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, page, err := parsePageToken(pt.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, err
	}

	userEntries, nextPage, err := u.client.LdapSearch(
		ctx,
		userFilter,
		nil,
		page,
		uint32(ResourcesPageSize),
		"",
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("ldap-connector: failed to list users: %w", err)
	}

	pageToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, "", nil, err
	}

	var rv []*v2.Resource
	for _, userEntry := range userEntries {
		userEntryCopy := userEntry

		ur, err := userResource(ctx, userEntryCopy)
		if err != nil {
			return nil, pageToken, nil, err
		}

		rv = append(rv, ur)
	}

	return rv, pageToken, nil, nil
}

func (u *userResourceType) Entitlements(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (u *userResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func userBuilder(client *ldap.Client) *userResourceType {
	return &userResourceType{
		resourceType: resourceTypeUser,
		client:       client,
	}
}
