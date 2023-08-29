package ldap

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/jackc/puddle/v2"
	"go.uber.org/zap"
)

type ldapConn struct {
	conn   *ldap.Conn
	baseDN string
}

type clientPool = *puddle.Pool[*ldapConn]

const (
	clientPoolSize     = 5
	maxConnectAttempts = clientPoolSize + 1
	defaultPageSize    = 100
)

type Client struct {
	pool clientPool
}

type Entry = ldap.Entry

func (c *Client) getConnection(ctx context.Context, isModify bool, f func(client *ldapConn) error) error {
	l := ctxzap.Extract(ctx)

	connectAttempts := 0
	for connectAttempts < maxConnectAttempts {
		cp, err := c.pool.Acquire(ctx)
		if err != nil {
			l.Error("baton-ldap: client failed to acquire connection", zap.Error(err))
			return err
		}
		poolClient := cp.Value()

		err = f(poolClient)
		if err != nil {
			if ldap.IsErrorWithCode(err, 200) {
				cp.Destroy()
				connectAttempts++
				continue
			}
			// If we are revoking a user's membership from a resource, and the user is not a member of the resource, we don't want to return an error.
			// If we are adding a user to a resource, and the user is already a member of the resource, we also don't want to return an error.
			if (ldap.IsErrorWithCode(err, 68) || ldap.IsErrorWithCode(err, 53)) && isModify {
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
		if baseDNOverride == "" {
			baseDNOverride = client.baseDN
			scope = ldap.ScopeWholeSubtree
		}

		if filter == "" {
			filter = "(objectClass=*)"
		}

		resp, err := client.conn.Search(&ldap.SearchRequest{
			BaseDN:       baseDNOverride,
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

	err := c.getConnection(ctx, true, func(client *ldapConn) error {
		return client.conn.Modify(modifyRequest)
	})
	if err != nil {
		l.Error("baton-ldap: client failed to modify record", zap.Error(err))
		return err
	}

	return nil
}

func TestConnection(domain string) (*ldap.Conn, error) {
	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s", domain))
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func getConnection(ctx context.Context, serverAddr string, password string, userDN string) (*ldap.Conn, error) {
	l := ctxzap.Extract(ctx)

	conn, err := TestConnection(serverAddr)
	if err != nil {
		l.Error("Failed to dial LDAP server", zap.Error(err))
		return nil, err
	}

	err = conn.Bind(userDN, password)
	if err != nil {
		l.Error("Failed to bind to LDAP server", zap.Error(err))
		return nil, err
	}

	return conn, nil
}

func NewClient(ctx context.Context, serverAddr string, baseDN string, password string, userDN string) (*Client, error) {
	_, err := getConnection(ctx, serverAddr, password, userDN)
	if err != nil {
		return nil, err
	}

	constructor := func(context.Context) (*ldapConn, error) {
		conn, err := getConnection(ctx, serverAddr, password, userDN)
		if err != nil {
			return nil, err
		}

		return &ldapConn{
			conn:   conn,
			baseDN: baseDN,
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
