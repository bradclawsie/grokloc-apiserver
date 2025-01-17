package client

import (
	"context"
	"errors"
	"net/http"
	testing_ "testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
)

func TestUser(t *testing_.T) {
	t.Run("CreateUserAsRoot", func(t *testing_.T) {
		ev := user.CreateEvent{
			DisplayName: safe.TrustedVarChar(security.RandString()),
			Email:       safe.TrustedVarChar(security.RandString()),
			Org:         o.ID,
			Password:    safe.TrustedPassword(security.RandString()),
		}
		_, createErr := rootClient.CreateUser(ev.DisplayName, ev.Email, ev.Org, ev.Password)
		require.NoError(t, createErr)
	})

	t.Run("CreateUserAsOrgOwner", func(t *testing_.T) {
		ev := user.CreateEvent{
			DisplayName: safe.TrustedVarChar(security.RandString()),
			Email:       safe.TrustedVarChar(security.RandString()),
			Org:         o.ID,
			Password:    safe.TrustedPassword(security.RandString()),
		}
		_, createErr := orgOwnerClient.CreateUser(ev.DisplayName, ev.Email, ev.Org, ev.Password)
		require.NoError(t, createErr)
		ev = user.CreateEvent{
			DisplayName: safe.TrustedVarChar(security.RandString()),
			Email:       safe.TrustedVarChar(security.RandString()),
			Org:         st.Root.Org,
			Password:    safe.TrustedPassword(security.RandString()),
		}
		_, createErr = orgOwnerClient.CreateUser(ev.DisplayName, ev.Email, ev.Org, ev.Password)
		var rErr ResponseErr
		require.True(t, errors.As(createErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("CreateUserAsRegularUser", func(t *testing_.T) {
		ev := user.CreateEvent{
			DisplayName: safe.TrustedVarChar(security.RandString()),
			Email:       safe.TrustedVarChar(security.RandString()),
			Org:         o.ID,
			Password:    safe.TrustedPassword(security.RandString()),
		}
		_, createErr := regularUserClient.CreateUser(ev.DisplayName, ev.Email, ev.Org, ev.Password)
		var rErr ResponseErr
		require.True(t, errors.As(createErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("ReadUserAsRoot", func(t *testing_.T) {
		_, readErr := rootClient.ReadUser(regularUser.ID)
		require.NoError(t, readErr)
		_, readErr = rootClient.ReadUser(models.NewID())
		var rErr ResponseErr
		require.True(t, errors.As(readErr, &rErr))
		require.Equal(t, http.StatusNotFound, rErr.StatusCode)
	})

	t.Run("ReadUserAsOrgOwner", func(t *testing_.T) {
		_, readErr := orgOwnerClient.ReadUser(regularUser.ID)
		require.NoError(t, readErr)
		_, readErr = orgOwnerClient.ReadUser(st.Root.ID)
		var rErr ResponseErr
		require.True(t, errors.As(readErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("ReadUserAsRegularUser", func(t *testing_.T) {
		_, readErr := regularUserClient.ReadUser(regularUser.ID)
		require.NoError(t, readErr)
		_, readErr = regularUserClient.ReadUser(st.Root.ID)
		var rErr ResponseErr
		require.True(t, errors.As(readErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
		_, readErr = regularUserClient.ReadUser(orgOwner.ID)
		require.True(t, errors.As(readErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("UpdateUserAPISecretAsRoot", func(t *testing_.T) {
		_, updateErr := rootClient.UpdateUserAPISecret(regularUser.ID)
		require.NoError(t, updateErr)
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()
		u, readErr := user.Read(context.Background(), conn.Conn(), st.VersionKey, regularUser.ID)
		require.NoError(t, readErr)
		regularUserClient.apiSecret = u.APISecret
		require.NoError(t, regularUserClient.newToken())
		_, updateErr = rootClient.UpdateUserAPISecret(models.NewID())
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusNotFound, rErr.StatusCode)
	})

	t.Run("UpdateUserAPISecretAsOrgOwner", func(t *testing_.T) {
		_, updateErr := orgOwnerClient.UpdateUserAPISecret(regularUser.ID)
		require.NoError(t, updateErr)
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()
		u, readErr := user.Read(context.Background(), conn.Conn(), st.VersionKey, regularUser.ID)
		require.NoError(t, readErr)
		regularUserClient.apiSecret = u.APISecret
		require.NoError(t, regularUserClient.newToken())
		_, updateErr = orgOwnerClient.UpdateUserAPISecret(st.Root.ID)
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("UpdateUserAPISecretAsRegularUser", func(t *testing_.T) {
		_, updateErr := regularUserClient.UpdateUserAPISecret(regularUser.ID)
		require.NoError(t, updateErr)
		_, updateErr = regularUserClient.UpdateUserAPISecret(st.Root.ID)
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
		_, updateErr = regularUserClient.UpdateUserAPISecret(orgOwner.ID)
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("UpdateUserDisplayNameAsRoot", func(t *testing_.T) {
		_, updateErr := rootClient.UpdateUserDisplayName(regularUser.ID, safe.TrustedVarChar(security.RandString()))
		require.NoError(t, updateErr)
		_, updateErr = rootClient.UpdateUserDisplayName(models.NewID(), safe.TrustedVarChar(security.RandString()))
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusNotFound, rErr.StatusCode)
	})

	t.Run("UpdateUserDisplayNameAsOrgOwner", func(t *testing_.T) {
		_, updateErr := orgOwnerClient.UpdateUserDisplayName(regularUser.ID, safe.TrustedVarChar(security.RandString()))
		require.NoError(t, updateErr)
		_, updateErr = orgOwnerClient.UpdateUserDisplayName(st.Root.ID, safe.TrustedVarChar(security.RandString()))
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("UpdateUserDisplayNameAsRegularUser", func(t *testing_.T) {
		_, updateErr := regularUserClient.UpdateUserDisplayName(regularUser.ID, safe.TrustedVarChar(security.RandString()))
		require.NoError(t, updateErr)
		_, updateErr = regularUserClient.UpdateUserDisplayName(st.Root.ID, safe.TrustedVarChar(security.RandString()))
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
		_, updateErr = regularUserClient.UpdateUserDisplayName(orgOwner.ID, safe.TrustedVarChar(security.RandString()))
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("UpdateUserPasswordAsRoot", func(t *testing_.T) {
		_, updateErr := rootClient.UpdateUserPassword(st.Root.ID, safe.TrustedPassword(security.RandString()))
		require.NoError(t, updateErr)
		_, updateErr = rootClient.UpdateUserPassword(regularUser.ID, safe.TrustedPassword(security.RandString()))
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
		_, updateErr = rootClient.UpdateUserPassword(models.NewID(), safe.TrustedPassword(security.RandString()))
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusNotFound, rErr.StatusCode)
	})

	t.Run("UpdateUserPasswordAsOrgOwner", func(t *testing_.T) {
		_, updateErr := orgOwnerClient.UpdateUserPassword(orgOwner.ID, safe.TrustedPassword(security.RandString()))
		require.NoError(t, updateErr)
		_, updateErr = orgOwnerClient.UpdateUserPassword(regularUser.ID, safe.TrustedPassword(security.RandString()))
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
		_, updateErr = orgOwnerClient.UpdateUserPassword(models.NewID(), safe.TrustedPassword(security.RandString()))
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusNotFound, rErr.StatusCode)
	})

	t.Run("UpdateUserPasswordAsRegularUser", func(t *testing_.T) {
		_, updateErr := regularUserClient.UpdateUserPassword(regularUser.ID, safe.TrustedPassword(security.RandString()))
		require.NoError(t, updateErr)
		_, updateErr = regularUserClient.UpdateUserPassword(st.Root.ID, safe.TrustedPassword(security.RandString()))
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
		_, updateErr = regularUserClient.UpdateUserPassword(orgOwner.ID, safe.TrustedPassword(security.RandString()))
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("UpdateUserStatusAsRoot", func(t *testing_.T) {
		_, updateErr := rootClient.UpdateUserStatus(regularUser.ID, models.StatusInactive)
		require.NoError(t, updateErr)
		_, updateErr = rootClient.UpdateUserStatus(regularUser.ID, models.StatusActive)
		require.NoError(t, updateErr)
		_, updateErr = rootClient.UpdateUserStatus(models.NewID(), models.StatusInactive)
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusNotFound, rErr.StatusCode)
	})

	t.Run("UpdateUserStatusAsOrgOwner", func(t *testing_.T) {
		_, updateErr := orgOwnerClient.UpdateUserStatus(regularUser.ID, models.StatusInactive)
		require.NoError(t, updateErr)
		_, updateErr = orgOwnerClient.UpdateUserStatus(regularUser.ID, models.StatusActive)
		require.NoError(t, updateErr)
		_, updateErr = orgOwnerClient.UpdateUserStatus(st.Root.ID, models.StatusInactive)
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("UpdateUserStatusAsRegularUser", func(t *testing_.T) {
		_, updateErr := regularUserClient.UpdateUserStatus(regularUser.ID, models.StatusActive)
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
		_, updateErr = regularUserClient.UpdateUserStatus(st.Root.ID, models.StatusActive)
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
		_, updateErr = regularUserClient.UpdateUserStatus(orgOwner.ID, models.StatusActive)
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})
}
