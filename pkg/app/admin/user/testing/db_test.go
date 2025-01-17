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
	t.Run("Encrypted", func(t *testing_.T) {
		t.Parallel()
		keyVersion, key, keyErr := st.VersionKey.GetCurrent()
		require.NoError(t, keyErr)
		displayName := safe.TrustedVarChar(security.RandString())
		email := safe.TrustedVarChar(security.RandString())
		org := models.NewID()
		password, passwordErr := security.DerivePassword(security.RandString(), st.Argon2Config)
		require.NoError(t, passwordErr)
		u, uErr := user.New(displayName, email, org, *password)
		require.NoError(t, uErr)
		apiSecret := u.APISecret
		encryptErr := u.Encrypt(key, keyVersion)
		require.NoError(t, encryptErr)

		// Capture an encrypted field and then re-encrypt to
		// ensure that Encrypt is idempotent.
		encryptedDisplayName := u.DisplayName
		encryptErr = u.Encrypt(key, keyVersion)
		require.NoError(t, encryptErr)
		require.Equal(t, encryptedDisplayName.String(), u.DisplayName.String())

		decryptErr := u.Decrypt(st.VersionKey)
		require.NoError(t, decryptErr)
		require.Equal(t, apiSecret.String(), u.APISecret.String())
		require.Equal(t, displayName.String(), u.DisplayName.String())
		require.Equal(t, email.String(), u.Email.String())

		// Decrypt again to show that Decrypt is idempotent.
		decryptErr = u.Decrypt(st.VersionKey)
		require.NoError(t, decryptErr)
		require.Equal(t, apiSecret.String(), u.APISecret.String())
		require.Equal(t, displayName.String(), u.DisplayName.String())
		require.Equal(t, email.String(), u.Email.String())
	})

	t.Run("ReadMiss", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		_, readErr := user.Read(context.Background(), conn.Conn(), st.VersionKey, models.NewID())
		require.Equal(t, models.ErrNotFound, readErr)
	})

	t.Run("InsertRead", func(t *testing_.T) {
		t.Parallel()
		keyVersion, key, keyErr := st.VersionKey.GetCurrent()
		require.NoError(t, keyErr)
		displayName := safe.TrustedVarChar(security.RandString())
		email := safe.TrustedVarChar(security.RandString())
		org := models.NewID()
		password, passwordErr := security.DerivePassword(security.RandString(), st.Argon2Config)
		require.NoError(t, passwordErr)

		u, uErr := user.New(displayName, email, org, *password)
		require.NoError(t, uErr)
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		require.NoError(t, u.Insert(
			context.Background(),
			conn.Conn(),
			keyVersion,
			key,
		))

		// duplicate
		require.Equal(t, models.ErrConflict,
			u.Insert(
				context.Background(),
				conn.Conn(),
				keyVersion,
				key,
			))

		// read
		uRead, readErr := user.Read(context.Background(), conn.Conn(), st.VersionKey, u.ID)
		require.NoError(t, readErr)
		require.Equal(t, u.ID, uRead.ID)
		require.Equal(t, u.APISecret, uRead.APISecret)
		require.Equal(t, u.APISecretDigest, uRead.APISecretDigest)
		require.Equal(t, u.DisplayName, uRead.DisplayName)
		require.Equal(t, u.DisplayNameDigest, uRead.DisplayNameDigest)
		require.Equal(t, u.Email, uRead.Email)
		require.Equal(t, u.EmailDigest, uRead.EmailDigest)
		// u does not have KeyVersion set yet
		require.NotEqual(t, u.KeyVersion, uRead.KeyVersion)
		require.Equal(t, u.Org, uRead.Org)
		require.Equal(t, u.Password, uRead.Password) // both derived already
		require.NotEqual(t, u.Meta.Ctime, uRead.Meta.Ctime)
		require.NotEqual(t, u.Meta.Mtime, uRead.Meta.Mtime)
		require.Equal(t, u.Meta.SchemaVersion, uRead.Meta.SchemaVersion)
		require.NotEqual(t, u.Meta.Signature, uRead.Meta.Signature)
		require.Equal(t, u.Meta.Role, uRead.Meta.Role)
		require.Equal(t, u.Meta.Status, uRead.Meta.Status)
	})

	t.Run("Create", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		orgName := safe.TrustedVarChar(security.RandString())
		ownerDisplayName := safe.TrustedVarChar(security.RandString())
		ownerEmail := safe.TrustedVarChar(security.RandString())
		ownerPassword, ownerPasswordErr := security.DerivePassword(security.RandString(), st.Argon2Config)
		require.NoError(t, ownerPasswordErr)

		o, _, orgCreateErr := org.Create(context.Background(),
			conn.Conn(),
			orgName,
			ownerDisplayName,
			ownerEmail,
			*ownerPassword,
			models.RoleTest,
			st.VersionKey)
		require.NoError(t, orgCreateErr)

		displayName := safe.TrustedVarChar(security.RandString())
		email := safe.TrustedVarChar(security.RandString())
		password, passwordErr := security.DerivePassword(security.RandString(), st.Argon2Config)
		require.NoError(t, passwordErr)

		u, uCreateErr := user.Create(context.Background(), conn.Conn(), displayName, email, o.ID, *password, st.VersionKey)
		require.NoError(t, uCreateErr)
		require.Equal(t, models.RoleTest, u.Meta.Role)
		require.Equal(t, o.ID, u.Org)
	})

	t.Run("CreateOrgMissing", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		displayName := safe.TrustedVarChar(security.RandString())
		email := safe.TrustedVarChar(security.RandString())
		password, passwordErr := security.DerivePassword(security.RandString(), st.Argon2Config)
		require.NoError(t, passwordErr)

		_, uCreateErr := user.Create(context.Background(), conn.Conn(), displayName, email, models.NewID(), *password, st.VersionKey)
		require.Equal(t, models.ErrNotFound, uCreateErr)
	})

	t.Run("CreateOrgInactive", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		orgName := safe.TrustedVarChar(security.RandString())
		ownerDisplayName := safe.TrustedVarChar(security.RandString())
		ownerEmail := safe.TrustedVarChar(security.RandString())
		ownerPassword, ownerPasswordErr := security.DerivePassword(security.RandString(), st.Argon2Config)
		require.NoError(t, ownerPasswordErr)

		o, _, orgCreateErr := org.Create(context.Background(),
			conn.Conn(),
			orgName,
			ownerDisplayName,
			ownerEmail,
			*ownerPassword,
			models.RoleTest,
			st.VersionKey)
		require.NoError(t, orgCreateErr)

		statusUpdateErr := models.Update(context.Background(),
			conn.Conn(),
			"orgs",
			o.ID,
			"status",
			models.StatusInactive)
		require.NoError(t, statusUpdateErr)

		displayName := safe.TrustedVarChar(security.RandString())
		email := safe.TrustedVarChar(security.RandString())
		password, passwordErr := security.DerivePassword(security.RandString(), st.Argon2Config)
		require.NoError(t, passwordErr)

		_, uCreateErr := user.Create(context.Background(), conn.Conn(), displayName, email, o.ID, *password, st.VersionKey)
		require.Equal(t, models.ErrRelatedOrg, uCreateErr)
	})

	t.Run("ReEncrypt", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		_, _, u, createErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, createErr)

		keyVersion, _, keyErr := st.VersionKey.GetCurrent()
		require.NoError(t, keyErr)
		reEncryptErr := u.ReEncrypt(context.Background(), conn.Conn(), keyVersion, st.VersionKey)
		require.NoError(t, reEncryptErr)

		uRead, readErr := user.Read(context.Background(), conn.Conn(), st.VersionKey, u.ID)
		require.NoError(t, readErr)
		require.Equal(t, u.APISecret.String(), uRead.APISecret.String())
		require.Equal(t, u.DisplayName.String(), uRead.DisplayName.String())
		require.Equal(t, u.Email.String(), uRead.Email.String())
	})

	t.Run("UpdateAPISecret", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		_, _, u, createErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, createErr)

		priorAPISecret := u.APISecret
		priorMeta := u.Meta

		apiSecretUpdateErr := u.UpdateAPISecret(context.Background(),
			conn.Conn(),
			st.VersionKey)
		require.NoError(t, apiSecretUpdateErr)

		require.NotEqual(t, priorAPISecret, u.APISecret)
		require.NotEqual(t, priorMeta.Signature, u.Meta.Signature)
	})

	t.Run("UpdateDisplayName", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		_, _, u, createErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, createErr)

		priorMeta := u.Meta

		newDisplayName := safe.TrustedVarChar(security.RandString())
		newDisplayNameDigest := security.EncodedSHA256(newDisplayName.String())

		displayNameUpdateErr := u.UpdateDisplayName(context.Background(),
			conn.Conn(),
			st.VersionKey,
			newDisplayName)
		require.NoError(t, displayNameUpdateErr)

		require.Equal(t, newDisplayName, u.DisplayName)
		require.Equal(t, newDisplayNameDigest, u.DisplayNameDigest)
		require.NotEqual(t, priorMeta.Signature, u.Meta.Signature)
	})

	t.Run("UpdatePassword", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		_, _, u, createErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, createErr)

		priorMeta := u.Meta

		newPassword, newPasswordErr := security.DerivePassword(security.RandString(), st.Argon2Config)
		require.NoError(t, newPasswordErr)

		passwordUpdateErr := u.UpdatePassword(context.Background(),
			conn.Conn(),
			st.VersionKey,
			*newPassword)
		require.NoError(t, passwordUpdateErr)

		require.Equal(t, newPassword.String(), u.Password.String())
		require.NotEqual(t, priorMeta.Signature, u.Meta.Signature)
	})

	t.Run("UpdateStatus", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		_, _, u, createErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, createErr)

		priorMeta := u.Meta

		statusUpdateErr := u.UpdateStatus(context.Background(),
			conn.Conn(),
			st.VersionKey,
			models.StatusInactive)
		require.NoError(t, statusUpdateErr)

		require.Equal(t, models.StatusInactive, u.Meta.Status)
		require.NotEqual(t, priorMeta.Signature, u.Meta.Signature)
	})
}
