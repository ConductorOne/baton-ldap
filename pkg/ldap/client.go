package ldap

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/jackc/puddle/v2"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ldapConn struct {
	conn               *ldap.Conn
	insecureSkipVerify bool
}

type clientPool = *puddle.Pool[*ldapConn]

const (
	clientPoolSize     = 5
	maxConnectAttempts = clientPoolSize + 10
	defaultPageSize    = 100
)

type Client struct {
	pool   clientPool
	filter string
}

type Entry = ldap.Entry

func isNetworkError(err error) bool {
	if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
		return true
	}

	// The ldap client library sometimes returns an error with this message when it's actually a network error
	if strings.HasPrefix(err.Error(), "unable to read LDAP response packet") {
		return true
	}

	return false
}

func (c *Client) getConnection(ctx context.Context, isModify bool, f func(client *ldapConn) error) error {
	l := ctxzap.Extract(ctx)

	var err error
	connectAttempts := 0
	for connectAttempts < maxConnectAttempts {
		if connectAttempts > 0 {
			l.Warn("baton-ldap: retrying connection", zap.Int("attempts", connectAttempts), zap.Int("maxAttempts", maxConnectAttempts))
			time.Sleep(time.Duration(connectAttempts) * time.Second)
		}
		var cp *puddle.Resource[*ldapConn]
		cp, err = c.pool.Acquire(ctx)
		if err != nil {
			if isNetworkError(err) {
				l.Warn("baton-ldap: network error acquiring connection. retrying", zap.Error(err), zap.Int("attempts", connectAttempts), zap.Int("maxAttempts", maxConnectAttempts))
				if cp != nil {
					cp.Destroy()
				}
				connectAttempts++
				continue
			}

			l.Error("baton-ldap: client failed to acquire connection", zap.Error(err))
			return err
		}
		poolClient := cp.Value()

		err = f(poolClient)
		if err != nil {
			if isNetworkError(err) {
				l.Warn("baton-ldap: network error. retrying", zap.Error(err), zap.Int("attempts", connectAttempts), zap.Int("maxAttempts", maxConnectAttempts))
				cp.Destroy()
				connectAttempts++
				continue
			}

			// If we are revoking a user's membership from a resource, and the user is not a member of the resource, we don't want to return an error.
			// If we are adding a user to a resource, and the user is already a member of the resource, we also don't want to return an error.
			if ldap.IsErrorAnyOf(err,
				ldap.LDAPResultAttributeOrValueExists,
				ldap.LDAPResultEntryAlreadyExists,
				ldap.LDAPResultUnwillingToPerform,
				ldap.LDAPResultNoSuchAttribute,
			) && isModify {
				cp.Release()
				return nil
			}
			l.Error("baton-ldap: client failed to run function", zap.Error(err))
			cp.Release()
			return err
		}

		cp.Release()
		break
	}
	return err
}

func parsePageToken(pageToken string) (string, []byte, error) {
	if pageToken == "" {
		return "", nil, nil
	}
	parts := strings.SplitN(pageToken, ":", 2)
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("invalid page token")
	}
	decodedToken, err := base64.StdEncoding.DecodeString(parts[1])
	return parts[0], decodedToken, err
}

var requestId = 0

func encodePageToken(cookie []byte) string {
	if len(cookie) == 0 {
		return ""
	}
	requestId++
	requestId %= 100
	return fmt.Sprintf("%v:%v", requestId, base64.StdEncoding.EncodeToString(cookie))
}

// CalculateUIDAndGID returns the next valid values for UIDNumber and GIDNumber. That's the maximum stored increased by one.
func (c *Client) CalculateUIDAndGID(ctx context.Context, searchDomain *ldap.DN, pageSize uint32) (string, string, error) {
	var totalEntries []*ldap.Entry
	var page string

	for {
		userEntries, nextPage, err := c.LdapSearch(
			ctx,
			ldap.ScopeWholeSubtree,
			searchDomain,
			"(objectClass=posixAccount)",
			[]string{"*"},
			page,
			pageSize,
		)
		if err != nil {
			return "", "", fmt.Errorf("baton-ldap: failed to list users on CalculateUIDAndGID: %w", err)
		}

		totalEntries = append(totalEntries, userEntries...)

		if nextPage == "" {
			break
		}
		page = nextPage
	}

	maxUID := 0
	maxGID := 0

	for _, entry := range totalEntries {
		uVal := entry.GetAttributeValue("uidNumber")
		if uVal != "" {
			if i, err := strconv.Atoi(uVal); err == nil {
				maxUID = max(maxUID, i)
			}
		}

		gVal := entry.GetAttributeValue("gidNumber")
		if gVal != "" {
			if i, err := strconv.Atoi(gVal); err == nil {
				maxGID = max(maxGID, i)
			}
		}
	}

	return strconv.Itoa(maxUID + 1), strconv.Itoa(maxGID + 1), nil
}

func (c *Client) LdapGet(ctx context.Context,
	searchDN *ldap.DN,
	filter string,
	attrNames []string,
) (*ldap.Entry, error) {
	entries, _, err := c.LdapSearch(ctx, ldap.ScopeBaseObject, searchDN, filter, attrNames, "", 1)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("entry not found: %s", searchDN.String())
	}
	if len(entries) > 1 {
		return nil, fmt.Errorf("multiple entries found: %s", searchDN.String())
	}
	return entries[0], nil
}

func (c *Client) LdapGetWithStringDN(ctx context.Context,
	searchDN string,
	filter string,
	attrNames []string,
) (*ldap.Entry, error) {
	entries, _, err := c.LdapSearchWithStringDN(ctx, ldap.ScopeBaseObject, searchDN, filter, attrNames, "", 1)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		notFoundError := status.Errorf(codes.NotFound, "baton-ldap: no such object")
		return nil, notFoundError
	}
	if len(entries) > 1 {
		return nil, fmt.Errorf("multiple entries found: %s", searchDN)
	}
	return entries[0], nil
}

func (c *Client) LdapSearch(ctx context.Context,
	searchScope int,
	searchDN *ldap.DN,
	filter string,
	attrNames []string,
	pageToken string, pageSize uint32) ([]*ldap.Entry, string, error) {
	var baseDN string
	if searchDN != nil {
		baseDN = searchDN.String()
	}

	return c.LdapSearchWithStringDN(ctx, searchScope, baseDN, filter, attrNames, pageToken, pageSize)
}

func (c *Client) LdapSearchWithStringDN(ctx context.Context,
	searchScope int,
	searchDN string,
	filter string,
	attrNames []string,
	pageToken string, pageSize uint32) ([]*ldap.Entry, string, error) {
	if c.filter != "" {
		if filter == "" {
			filter = c.filter
		} else {
			filter = fmt.Sprintf("(&(%s)%s)", filter, c.filter)
		}
	}

	return c._ldapSearch(ctx, searchScope, searchDN, filter, attrNames, pageToken, pageSize, 0)
}

func (c *Client) _ldapSearch(ctx context.Context,
	searchScope int,
	searchDN string,
	filter string,
	attrNames []string,
	pageToken string,
	pageSize uint32,
	attempts int) ([]*ldap.Entry, string, error) {
	l := ctxzap.Extract(ctx)

	var ret []*ldap.Entry
	var nextPageToken string

	err := c.getConnection(ctx, false, func(client *ldapConn) error {
		if pageSize <= 0 {
			pageSize = defaultPageSize
		}

		pagingControl := ldap.NewControlPaging(pageSize)
		if pageToken != "" {
			_, decodedToken, err := parsePageToken(pageToken)
			if err != nil {
				return err
			}
			pagingControl.SetCookie(decodedToken)
		}

		if len(attrNames) == 0 {
			attrNames = []string{"*"}
		}

		if filter == "" {
			filter = "(objectClass=*)"
		}

		baseDN := searchDN

		l.Debug("searching for ldap entries", zap.String("search_dn", baseDN), zap.String("filter", filter), zap.Strings("attrNames", attrNames))

		resp, err := client.conn.Search(&ldap.SearchRequest{
			BaseDN:       baseDN,
			Scope:        searchScope,
			DerefAliases: ldap.DerefAlways,
			Filter:       filter,
			Attributes:   attrNames,
			Controls:     []ldap.Control{pagingControl},
		})
		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				notFoundError := status.Errorf(codes.NotFound, "baton-ldap: no such object")
				l.Warn("baton-ldap: no such object", zap.Error(err), zap.String("search_dn", baseDN), zap.String("filter", filter), zap.Strings("attrNames", attrNames))
				return errors.Join(notFoundError, err)
			}
			l.Error("baton-ldap: client failed to search", zap.Error(err))
			return err
		}

		ret = append(ret, resp.Entries...)

		resultPc := ldap.FindControl(resp.Controls, ldap.ControlTypePaging)
		if pc, ok := resultPc.(*ldap.ControlPaging); ok {
			nextPageToken = encodePageToken(pc.Cookie)
		}
		return nil
	})
	if err != nil {
		// LDAP page tokens don't persist across connections. Retry with no page token if that's the case.
		// This restarts a search from scratch, but baton-SDK will upsert instead of conflicting.
		if attempts == 0 && pageToken != "" && ldap.IsErrorAnyOf(err, ldap.LDAPResultUnwillingToPerform) {
			l.Info("Retrying search without page token", zap.Error(err), zap.String("filter", filter), zap.String("search_dn", searchDN))
			return c._ldapSearch(ctx, searchScope, searchDN, filter, attrNames, "", pageSize, attempts+1)
		}
		l.Error("baton-ldap: client failed to get connection", zap.Error(err))
		return nil, "", err
	}

	return ret, nextPageToken, nil
}

func (c *Client) LdapAdd(ctx context.Context, addRequest *ldap.AddRequest) error {
	l := ctxzap.Extract(ctx)

	l.Debug("adding ldap entry", zap.String("DN", addRequest.DN), zap.Any("attributes", addRequest.Attributes))

	err := c.getConnection(ctx, true, func(client *ldapConn) error {
		return client.conn.Add(addRequest)
	})
	if err != nil {
		l.Error("baton-ldap: client failed to add record", zap.Error(err))
		return err
	}

	return nil
}

func (c *Client) LdapModify(ctx context.Context, modifyRequest *ldap.ModifyRequest) error {
	l := ctxzap.Extract(ctx)

	l.Debug("modifying ldap entry", zap.String("DN", modifyRequest.DN), zap.Any("changes", modifyRequest.Changes))

	err := c.getConnection(ctx, true, func(client *ldapConn) error {
		return client.conn.Modify(modifyRequest)
	})
	if err != nil {
		l.Error("baton-ldap: client failed to modify record", zap.Error(err))
		return err
	}

	return nil
}

func (c *Client) LdapDelete(ctx context.Context, deleteRequest *ldap.DelRequest) error {
	l := ctxzap.Extract(ctx)

	l.Debug("deleting ldap entry", zap.String("DN", deleteRequest.DN))

	err := c.getConnection(ctx, true, func(client *ldapConn) error {
		return client.conn.Del(deleteRequest)
	})
	if err != nil {
		l.Error("baton-ldap: client failed to delete record", zap.Error(err))
		return err
	}

	return nil
}

func TestConnection(url string, insecureSkipVerify bool) (*ldap.Conn, error) {
	dialOpts := ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: insecureSkipVerify}) // #nosec G402
	conn, err := ldap.DialURL(url, dialOpts)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func getConnection(ctx context.Context, serverUrl string, password string, userDN string, insecureSkipVerify bool) (*ldap.Conn, error) {
	l := ctxzap.Extract(ctx)

	conn, err := TestConnection(serverUrl, insecureSkipVerify)
	if err != nil {
		l.Error("Failed to dial LDAP server", zap.Error(err))
		return nil, err
	}

	if password == "" {
		l.Debug("Binding to LDAP server unauthenticated")
		err = conn.UnauthenticatedBind(userDN)
	} else {
		l.Debug("Binding to LDAP server authenticated")
		err = conn.Bind(userDN, password)
	}
	if err != nil {
		l.Error("Failed to bind to LDAP server", zap.Error(err))
		return nil, err
	}

	return conn, nil
}

func NewClient(ctx context.Context, serverUrl string, password string, userDN string, insecureSkipVerify bool, filter string) (*Client, error) {
	_, err := getConnection(ctx, serverUrl, password, userDN, insecureSkipVerify)
	if err != nil {
		return nil, err
	}

	constructor := func(context.Context) (*ldapConn, error) {
		conn, err := getConnection(ctx, serverUrl, password, userDN, insecureSkipVerify)
		if err != nil {
			return nil, err
		}

		return &ldapConn{
			conn:               conn,
			insecureSkipVerify: insecureSkipVerify,
		}, nil
	}
	destructor := func(conn *ldapConn) {
		conn.conn.Close()
	}

	pool, err := puddle.NewPool(&puddle.Config[*ldapConn]{
		Constructor: constructor,
		Destructor:  destructor,
		MaxSize:     clientPoolSize,
	})
	if err != nil {
		return nil, err
	}

	return &Client{
		pool:   pool,
		filter: filter,
	}, nil
}
