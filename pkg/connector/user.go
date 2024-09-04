package connector

import (
	"context"
	"fmt"
	"strconv"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"

	"github.com/conductorone/baton-ldap/pkg/ldap"
)

// InetOrgPerson resource structure
// https://datatracker.ietf.org/doc/html/rfc2798
const (
	userFilter = "(objectClass=inetOrgPerson)"

	attrUserUID           = "uid"
	attrUserCommonName    = "cn"
	attrFirstName         = "givenName"
	attrLastName          = "sn"
	attrUserMail          = "mail"
	attrUserDisplayName   = "displayName"
	attrUserCreatedAt     = "createTimestamp"
	attrUserAuthTimestamp = "authTimestamp"
	attrObjectGUID        = "objectGUID"

	// Microsoft active directory specific attribute.
	attrsAMAccountName     = "sAMAccountName"
	attrUserPrincipalName  = "userPrincipalName"
	attrUserAccountControl = "userAccountControl"
	attrUserLastLogon      = "lastLogonTimestamp"
)

var allAttrs = []string{"*", "+"}

type userResourceType struct {
	resourceType            *v2.ResourceType
	client                  *ldap.Client
	disableOperationalAttrs bool
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

func parseUserLogin(user *ldap.Entry) (string, []string) {
	login := ""
	aliases := []string{}

	sAMAccountName := user.GetAttributeValue(attrsAMAccountName)
	uid := user.GetAttributeValue(attrUserUID)
	cn := user.GetAttributeValue(attrUserCommonName)
	principalName := user.GetAttributeValue(attrUserPrincipalName)
	guid := user.GetAttributeValue(attrObjectGUID)

	for _, attr := range []string{sAMAccountName, uid, cn, principalName, guid} {
		if attr == "" {
			continue
		}
		if login == "" {
			login = attr
			continue
		}
		if attr == login {
			continue
		}
		aliases = append(aliases, attr)
	}

	return login, aliases
}

func parseUserLastLogin(lastLoginStr string) (*time.Time, error) {
	lastLoginTime, err := time.Parse("20060102150405Z0700", lastLoginStr)
	if err == nil {
		lastLoginTime = lastLoginTime.UTC()
		return &lastLoginTime, nil
	}

	// Number of 100 nanosecond intervals since 1601: https://learn.microsoft.com/en-us/windows/win32/adschema/a-lastlogontimestamp
	lastLoginInt, err := strconv.ParseInt(lastLoginStr, 10, 64)
	if err != nil {
		return nil, err
	}
	lastLoginInt /= 10_000_000     // convert to seconds
	lastLoginInt -= 11_644_473_600 // seconds from 1601 to 1970
	lastLoginTime = time.Unix(lastLoginInt, 0).UTC()

	return &lastLoginTime, nil
}

// Create a new connector resource for an LDAP User.
func userResource(ctx context.Context, user *ldap.Entry) (*v2.Resource, error) {
	l := ctxzap.Extract(ctx)

	firstName, lastName, displayName := parseUserNames(user)
	userId := user.GetAttributeValue(attrUserUID)

	profile := map[string]interface{}{
		"user_id":    userId,
		"first_name": firstName,
		"last_name":  lastName,
		"path":       user.DN,
	}

	for _, v := range user.Attributes {
		if len(v.Values) == 1 {
			profile[v.Name] = v.Values[0]
		}
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
		rs.WithStatus(userStatus),
	}

	login, aliases := parseUserLogin(user)
	if login != "" {
		userTraitOptions = append(userTraitOptions, rs.WithUserLogin(login, aliases...))
		profile["login"] = login
	}

	userTraitOptions = append(userTraitOptions, rs.WithUserProfile(profile))

	createdAt := user.GetAttributeValue(attrUserCreatedAt)
	createTime, err := time.Parse("20060102150405Z0700", createdAt)
	if err == nil {
		userTraitOptions = append(userTraitOptions, rs.WithCreatedAt(createTime))
	}

	// Try openldap format first, then fall back to Active Directory's format
	lastLogin, err := parseUserLastLogin(user.GetAttributeValue(attrUserLastLogon))
	if err != nil {
		lastLogin, _ = parseUserLastLogin(user.GetAttributeValue(attrUserAuthTimestamp))
	}
	if lastLogin != nil {
		userTraitOptions = append(userTraitOptions, rs.WithLastLogin(*lastLogin))
	}

	// if no display name, use the user id
	if displayName == "" {
		displayName = userId
	}

	l.Debug("creating user resource", zap.String("display_name", displayName), zap.String("user_id", userId), zap.String("dn", user.DN))

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
	l := ctxzap.Extract(ctx)
	bag, page, err := parsePageToken(pt.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, err
	}

	attrs := allAttrs
	if u.disableOperationalAttrs {
		attrs = []string{"*"}
	}

	userEntries, nextPage, err := u.client.LdapSearch(
		ctx,
		userFilter,
		attrs,
		page,
		ResourcesPageSize,
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
		l.Debug("processing user", zap.String("dn", userEntry.DN))
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

func userBuilder(client *ldap.Client, disableOperationalAttrs bool) *userResourceType {
	return &userResourceType{
		resourceType:            resourceTypeUser,
		client:                  client,
		disableOperationalAttrs: disableOperationalAttrs,
	}
}
