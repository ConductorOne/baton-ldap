package connector

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUserLastLogin(t *testing.T) {
	// 133597695554218221 == 05/09/2024 11:05:55 PM
	lastLoginTime, err := parseUserLastLogin("133597695554218221")
	require.NoError(t, err)
	require.Equal(t, "2024-05-09 23:05:55 +0000 UTC", lastLoginTime.String())

	lastLoginTime, err = parseUserLastLogin("20200804154203Z")
	require.NoError(t, err)
	require.Equal(t, "2020-08-04 15:42:03 +0000 UTC", lastLoginTime.String())

	_, err = parseUserLastLogin("Not a date")
	require.Error(t, err)
}
