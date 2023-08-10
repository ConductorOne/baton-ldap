package ldap

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

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

func (c *Client) getConnection(ctx context.Context, f func(client *ldapConn) error) error {
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
			l.Error("baton-ldap: client failed to run function", zap.Error(err))
			cp.Release()
			return err
		}

		cp.Release()
		break
	}
	return nil
}

func (c *Client) LdapSearch(ctx context.Context, filter string, attrNames []string, pageToken string, pageSize uint32) ([]*ldap.Entry, string, error) {
	l := ctxzap.Extract(ctx)

	var ret []*ldap.Entry
	var nextPageToken string

	err := c.getConnection(ctx, func(client *ldapConn) error {
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

		resp, err := client.conn.Search(&ldap.SearchRequest{
			BaseDN:       client.baseDN,
			Scope:        ldap.ScopeWholeSubtree,
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

func (c *Client) CreateMemberEntry(memberId string, sampleDN string) (string, error) {
	sampleMemberDN, err := ldap.ParseDN(sampleDN)
	if err != nil {
		return "", fmt.Errorf("baton-ldap: failed to parse member DN %s: %w", sampleDN, err)
	}

	var memberBaseDN []string
	// compose memberBaseDN from sample RDNs
	for _, rdn := range sampleMemberDN.RDNs[1:] {
		memberBaseDN = append(memberBaseDN, rdn.String())
	}

	return fmt.Sprintf("uid=%s,%s", memberId, strings.Join(memberBaseDN, ",")), nil
}

func (c *Client) LdapModify(ctx context.Context, dn string, attr string, newValues []string) error {
	l := ctxzap.Extract(ctx)

	err := c.getConnection(ctx, func(client *ldapConn) error {
		modifyRequest := ldap.NewModifyRequest(dn, nil)

		modifyRequest.Replace(attr, newValues)

		return client.conn.Modify(modifyRequest)
	})
	if err != nil {
		l.Error("baton-ldap: client failed to get connection", zap.Error(err))
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

func getConnection(ctx context.Context, serverAddr string, password string) (*ldap.Conn, error) {
	l := ctxzap.Extract(ctx)

	conn, err := TestConnection(serverAddr)
	if err != nil {
		l.Error("Failed to dial LDAP server", zap.Error(err))
		return nil, err
	}

	err = conn.Bind("cn=admin,dc=example,dc=org", password)
	if err != nil {
		l.Error("Failed to bind to LDAP server", zap.Error(err))
		return nil, err
	}

	return conn, nil
}

func NewClient(ctx context.Context, serverAddr string, baseDN string, password string) (*Client, error) {
	_, err := getConnection(ctx, serverAddr, password)
	if err != nil {
		return nil, err
	}

	constructor := func(context.Context) (*ldapConn, error) {
		conn, err := getConnection(ctx, serverAddr, password)
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
