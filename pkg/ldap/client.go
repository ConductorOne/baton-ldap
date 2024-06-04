package ldap

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/jackc/puddle/v2"
	"go.uber.org/zap"
)

type ldapConn struct {
	conn               *ldap.Conn
	baseDN             string
	insecureSkipVerify bool
}

type clientPool = *puddle.Pool[*ldapConn]

const (
	clientPoolSize     = 5
	maxConnectAttempts = clientPoolSize + 10
	defaultPageSize    = 100
)

type Client struct {
	pool clientPool
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

	connectAttempts := 0
	for connectAttempts < maxConnectAttempts {
		if connectAttempts > 0 {
			l.Warn("baton-ldap: retrying connection", zap.Int("attempts", connectAttempts), zap.Int("maxAttempts", maxConnectAttempts))
			time.Sleep(time.Duration(connectAttempts) * time.Second)
		}
		cp, err := c.pool.Acquire(ctx)
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
			if ldap.IsErrorAnyOf(err, ldap.LDAPResultAttributeOrValueExists, ldap.LDAPResultEntryAlreadyExists, ldap.LDAPResultUnwillingToPerform) && isModify {
				return nil
			}
			l.Error("baton-ldap: client failed to run function", zap.Error(err))
			cp.Release()
			return err
		}

		cp.Release()
		break
	}
	return nil
}

func (c *Client) LdapSearch(ctx context.Context, filter string, attrNames []string, pageToken string, pageSize uint32, baseDNOverride string) ([]*ldap.Entry, string, error) {
	l := ctxzap.Extract(ctx)

	var ret []*ldap.Entry
	var nextPageToken string

	// TODO (ggreer): Reconnecting with a pageToken doesn't work because the ldap cookie is per-connection
	// To fix this, we should restart the query with no pageToken
	err := c.getConnection(ctx, false, func(client *ldapConn) error {
		if pageSize <= 0 {
			pageSize = defaultPageSize
		}

		pagingControl := ldap.NewControlPaging(pageSize)
		if pageToken != "" {
			decodedToken, err := base64.StdEncoding.DecodeString(pageToken)
			if err != nil {
				return err
			}
			pagingControl.SetCookie(decodedToken)
		}

		if len(attrNames) == 0 {
			attrNames = []string{"*"}
		}
		scope := ldap.ScopeBaseObject

		// This function gets called on retries, so don't change the value of args, otherwise we don't set scope
		baseDN := baseDNOverride
		if baseDN == "" {
			baseDN = client.baseDN
			scope = ldap.ScopeWholeSubtree
		}

		if filter == "" {
			filter = "(objectClass=*)"
		}

		l.Debug("searching for ldap entries", zap.String("baseDN", baseDN), zap.String("filter", filter), zap.Strings("attrNames", attrNames))

		resp, err := client.conn.Search(&ldap.SearchRequest{
			BaseDN:       baseDN,
			Scope:        scope,
			DerefAliases: ldap.DerefAlways,
			Filter:       filter,
			Attributes:   attrNames,
			Controls:     []ldap.Control{pagingControl},
		})
		if err != nil {
			l.Error("baton-ldap: client failed to search", zap.Error(err))
			return err
		}

		ret = append(ret, resp.Entries...)

		resultPc := ldap.FindControl(resp.Controls, ldap.ControlTypePaging)
		if pc, ok := resultPc.(*ldap.ControlPaging); ok {
			nextPageToken = base64.StdEncoding.EncodeToString(pc.Cookie)
		}
		return nil
	})
	if err != nil {
		l.Error("baton-ldap: client failed to get connection", zap.Error(err))
		return nil, "", err
	}

	return ret, nextPageToken, nil
}

func (c *Client) CreateMemberEntry(ctx context.Context, memberId string) (string, error) {
	memberEntry, _, err := c.LdapSearch(
		ctx,
		"",
		nil,
		"",
		1,
		memberId,
	)
	if err != nil {
		return "", fmt.Errorf("ldap-connector: failed to get user with id %s: %w", memberId, err)
	}
	if len(memberEntry) == 0 {
		return "", fmt.Errorf("ldap-connector: no user with id %s found", memberId)
	}

	return memberEntry[0].DN, nil
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

func NewClient(ctx context.Context, serverUrl string, baseDN string, password string, userDN string, insecureSkipVerify bool) (*Client, error) {
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
			baseDN:             baseDN,
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
		pool: pool,
	}, nil
}
