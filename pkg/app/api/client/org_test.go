package client

import (
	"errors"
	"net/http"
	testing_ "testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
)

func TestOrg(t *testing_.T) {
	t.Run("CreateOrgAsRoot", func(t *testing_.T) {
		ev := org.CreateEvent{
			Name:             safe.TrustedVarChar(security.RandString()),
			OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
			OwnerEmail:       safe.TrustedVarChar(security.RandString()),
			OwnerPassword:    safe.TrustedPassword(security.RandString()),
			Role:             st.DefaultRole,
		}
		_, createErr := rootClient.CreateOrg(ev.Name, ev.OwnerDisplayName, ev.OwnerEmail, ev.OwnerPassword, ev.Role)
		require.NoError(t, createErr)
	})

	t.Run("CreateOrgAsOrgOwner", func(t *testing_.T) {
		ev := org.CreateEvent{
			Name:             safe.TrustedVarChar(security.RandString()),
			OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
			OwnerEmail:       safe.TrustedVarChar(security.RandString()),
			OwnerPassword:    safe.TrustedPassword(security.RandString()),
			Role:             st.DefaultRole,
		}
		_, createErr := orgOwnerClient.CreateOrg(ev.Name, ev.OwnerDisplayName, ev.OwnerEmail, ev.OwnerPassword, ev.Role)
		require.Error(t, createErr)
		var rErr ResponseErr
		require.True(t, errors.As(createErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("CreateOrgAsRegularUser", func(t *testing_.T) {
		ev := org.CreateEvent{
			Name:             safe.TrustedVarChar(security.RandString()),
			OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
			OwnerEmail:       safe.TrustedVarChar(security.RandString()),
			OwnerPassword:    safe.TrustedPassword(security.RandString()),
			Role:             st.DefaultRole,
		}
		_, createErr := regularUserClient.CreateOrg(ev.Name, ev.OwnerDisplayName, ev.OwnerEmail, ev.OwnerPassword, ev.Role)
		require.Error(t, createErr)
		var rErr ResponseErr
		require.True(t, errors.As(createErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("ReadOrgAsRoot", func(t *testing_.T) {
		_, readErr := rootClient.ReadOrg(o.ID)
		require.NoError(t, readErr)
		_, readErr = rootClient.ReadOrg(models.NewID())
		var rErr ResponseErr
		require.True(t, errors.As(readErr, &rErr))
		require.Equal(t, http.StatusNotFound, rErr.StatusCode)
	})

	t.Run("ReadOrgAsOrgOwner", func(t *testing_.T) {
		_, readErr := orgOwnerClient.ReadOrg(o.ID)
		require.NoError(t, readErr)
		_, readErr = orgOwnerClient.ReadOrg(models.NewID())
		var rErr ResponseErr
		require.True(t, errors.As(readErr, &rErr))
		require.Equal(t, http.StatusNotFound, rErr.StatusCode)
	})

	t.Run("ReadOrgAsRegularUser", func(t *testing_.T) {
		_, readErr := regularUserClient.ReadOrg(o.ID)
		var rErr ResponseErr
		require.True(t, errors.As(readErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("ReadOrgUsersAsRoot", func(t *testing_.T) {
		userIDs, readErr := rootClient.ReadOrgUsers(o.ID)
		require.NoError(t, readErr)
		require.NotEqual(t, 0, len(userIDs))
		_, readErr = rootClient.ReadOrgUsers(models.NewID())
		var rErr ResponseErr
		require.True(t, errors.As(readErr, &rErr))
		require.Equal(t, http.StatusNotFound, rErr.StatusCode)
	})

	t.Run("ReadOrgUsersAsOrgOwner", func(t *testing_.T) {
		userIDs, readErr := orgOwnerClient.ReadOrgUsers(o.ID)
		require.NoError(t, readErr)
		require.NotEqual(t, 0, len(userIDs))
		_, readErr = orgOwnerClient.ReadOrgUsers(models.NewID())
		var rErr ResponseErr
		require.True(t, errors.As(readErr, &rErr))
		require.Equal(t, http.StatusNotFound, rErr.StatusCode)
	})

	t.Run("ReadOrgUsersAsRegularUser", func(t *testing_.T) {
		_, readErr := regularUserClient.ReadOrgUsers(o.ID)
		var rErr ResponseErr
		require.True(t, errors.As(readErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("UpdateOrgOwnerAsRoot", func(t *testing_.T) {
		_, updateErr := rootClient.UpdateOrgOwner(o.ID, regularUser.ID)
		require.NoError(t, updateErr)
		_, updateErr = rootClient.UpdateOrgOwner(o.ID, orgOwner.ID)
		require.NoError(t, updateErr)
		_, updateErr = rootClient.UpdateOrgOwner(models.NewID(), orgOwner.ID)
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusNotFound, rErr.StatusCode)
	})

	t.Run("UpdateOrgOwnerAsOrgOwner", func(t *testing_.T) {
		_, updateErr := orgOwnerClient.UpdateOrgOwner(o.ID, regularUser.ID)
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("UpdateOrgOwnerAsRegularUser", func(t *testing_.T) {
		_, updateErr := regularUserClient.UpdateOrgOwner(o.ID, regularUser.ID)
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("UpdateOrgStatusAsRoot", func(t *testing_.T) {
		_, updateErr := rootClient.UpdateOrgStatus(o.ID, models.StatusInactive)
		require.NoError(t, updateErr)
		_, updateErr = rootClient.UpdateOrgStatus(o.ID, models.StatusActive)
		require.NoError(t, updateErr)
		_, updateErr = rootClient.UpdateOrgStatus(models.NewID(), models.StatusInactive)
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusNotFound, rErr.StatusCode)
	})

	t.Run("UpdateOrgStatusAsOrgOwner", func(t *testing_.T) {
		_, updateErr := orgOwnerClient.UpdateOrgStatus(o.ID, models.StatusInactive)
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("UpdateOrgStatusAsRegularUser", func(t *testing_.T) {
		_, updateErr := regularUserClient.UpdateOrgStatus(o.ID, models.StatusInactive)
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("DeleteOrgAsRoot", func(t *testing_.T) {
		updateErr := rootClient.DeleteOrg(o.ID)
		require.NoError(t, updateErr)
		_, updateErr = rootClient.UpdateOrgStatus(o.ID, models.StatusActive)
		require.NoError(t, updateErr)
		updateErr = rootClient.DeleteOrg(models.NewID())
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusNotFound, rErr.StatusCode)
	})

	t.Run("DeleteOrgAsOrgOwner", func(t *testing_.T) {
		updateErr := orgOwnerClient.DeleteOrg(o.ID)
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})

	t.Run("DeleteOrgAsRegularUser", func(t *testing_.T) {
		updateErr := regularUserClient.DeleteOrg(o.ID)
		var rErr ResponseErr
		require.True(t, errors.As(updateErr, &rErr))
		require.Equal(t, http.StatusForbidden, rErr.StatusCode)
	})
}
