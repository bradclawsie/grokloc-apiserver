package testing

import (
	"context"
	testing_ "testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
)

func TestDatabase(t *testing_.T) {
	t.Run("InsertRead", func(t *testing_.T) {
		t.Parallel()
		o := &org.Org{}
		o.ID = models.NewID()
		o.Name = safe.TrustedVarChar(security.RandString())
		o.Owner = models.NewID()
		o.Meta.Role = models.RoleTest
		o.Meta.Status = models.StatusActive

		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		require.NoError(t, o.Insert(context.Background(), conn.Conn()))

		// duplicate
		require.Equal(t, models.ErrConflict, o.Insert(context.Background(), conn.Conn()))

		// read
		oRead, readErr := org.Read(context.Background(), conn.Conn(), o.ID)
		require.NoError(t, readErr)
		require.Equal(t, o.ID, oRead.ID)
		require.Equal(t, o.Owner, oRead.Owner)
		require.Equal(t, o.Meta.Role, oRead.Meta.Role)
		require.Equal(t, o.Meta.Status, oRead.Meta.Status)
		require.Equal(t, o.Meta.SchemaVersion, oRead.Meta.SchemaVersion)
		require.NotEqual(t, o.Meta.Ctime, oRead.Meta.Ctime)
		require.NotEqual(t, o.Meta.Mtime, oRead.Meta.Mtime)
		require.NotEqual(t, o.Meta.Signature, oRead.Meta.Signature)
	})

	t.Run("ReadMiss", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		_, readErr := org.Read(context.Background(), conn.Conn(), models.NewID())
		require.Equal(t, models.ErrNotFound, readErr)
	})

	t.Run("Create", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		name := safe.TrustedVarChar(security.RandString())
		ownerDisplayName := safe.TrustedVarChar(security.RandString())
		ownerEmail := safe.TrustedVarChar(security.RandString())
		ownerPassword, passwordErr := security.DerivePassword(security.RandString(), st.Argon2Config)
		require.NoError(t, passwordErr)

		o, owner, createErr := org.Create(context.Background(),
			conn.Conn(),
			name,
			ownerDisplayName,
			ownerEmail,
			*ownerPassword,
			models.RoleTest,
			st.VersionKey)
		require.NoError(t, createErr)
		require.Equal(t, models.RoleTest, o.Meta.Role)
		require.Equal(t, o.Meta.Role, owner.Meta.Role)
		require.Equal(t, o.Owner, owner.ID)
		require.Equal(t, owner.Org, o.ID)
		require.Equal(t, name, o.Name)
		// DisplayName and Email are decrypted from Read(...)
		require.Equal(t, ownerDisplayName, owner.DisplayName)
		require.Equal(t, ownerEmail, owner.Email)
		require.Equal(t, *ownerPassword, owner.Password)
	})

	t.Run("Users", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		name := safe.TrustedVarChar(security.RandString())
		ownerDisplayName := safe.TrustedVarChar(security.RandString())
		ownerEmail := safe.TrustedVarChar(security.RandString())
		ownerPassword, passwordErr := security.DerivePassword(security.RandString(), st.Argon2Config)
		require.NoError(t, passwordErr)

		o, owner, createErr := org.Create(context.Background(),
			conn.Conn(),
			name,
			ownerDisplayName,
			ownerEmail,
			*ownerPassword,
			models.RoleTest,
			st.VersionKey)
		require.NoError(t, createErr)

		userIDs, userIDsErr := org.Users(context.Background(), conn.Conn(), o.ID)
		require.NoError(t, userIDsErr)
		require.Equal(t, 1, len(userIDs))
		require.Equal(t, owner.ID, userIDs[0])

		// add another user and retest
		displayName := safe.TrustedVarChar(security.RandString())
		email := safe.TrustedVarChar(security.RandString())
		password, passwordErr := security.DerivePassword(security.RandString(), st.Argon2Config)
		require.NoError(t, passwordErr)

		u, uCreateErr := user.Create(context.Background(), conn.Conn(), displayName, email, o.ID, *password, st.VersionKey)
		require.NoError(t, uCreateErr)
		userIDs, userIDsErr = org.Users(context.Background(), conn.Conn(), o.ID)
		require.NoError(t, userIDsErr)
		require.Equal(t, 2, len(userIDs))
		found := false
		for _, v := range userIDs {
			if v == u.ID {
				found = true
				break
			}
		}
		require.True(t, found)

		// test for an org that doesn't exist
		_, userIDsErr = org.Users(context.Background(), conn.Conn(), models.NewID())
		require.Equal(t, models.ErrNotFound, userIDsErr)
	})

	t.Run("UpdateStatus", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		o, _, _, createErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, createErr)

		priorMeta := o.Meta

		statusUpdateErr := o.UpdateStatus(context.Background(), conn.Conn(), models.StatusInactive)
		require.NoError(t, statusUpdateErr)
		require.NotEqual(t, priorMeta.Signature, o.Meta.Signature)
	})

	t.Run("UpdateOwner", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		o, _, u, createErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, createErr)

		// try updating o owner to owner that doesn't exist
		ownerUpdateErr := o.UpdateOwner(context.Background(), conn.Conn(), models.NewID())
		require.Equal(t, models.ErrRelatedUser, ownerUpdateErr)

		// change u status to unconfirmed for the next test
		statusUpdateErr := u.UpdateStatus(context.Background(),
			conn.Conn(),
			st.VersionKey,
			models.StatusInactive,
		)
		require.NoError(t, statusUpdateErr)

		// u is a non-owner user in o, try making it new owner
		// u has status unconfirmed as of update above
		ownerUpdateErr = o.UpdateOwner(context.Background(), conn.Conn(), u.ID)
		require.Equal(t, models.ErrRelatedUser, ownerUpdateErr)

		// update u status to active
		statusUpdateErr = u.UpdateStatus(context.Background(),
			conn.Conn(),
			st.VersionKey,
			models.StatusActive,
		)
		require.NoError(t, statusUpdateErr)
		ownerUpdateErr = o.UpdateOwner(context.Background(), conn.Conn(), u.ID)
		require.NoError(t, ownerUpdateErr)
		require.Equal(t, o.Owner, u.ID)

		// create a new "other" org, try to make u the owner of it
		other, _, _, otherErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, otherErr)

		// u is not a user in other, so this fails
		ownerUpdateErr = other.UpdateOwner(context.Background(), conn.Conn(), u.ID)
		require.Equal(t, models.ErrRelatedUser, ownerUpdateErr)
	})
}
