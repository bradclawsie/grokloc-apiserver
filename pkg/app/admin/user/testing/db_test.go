// Package testing breaks an import loop for user.
package testing

import (
	"context"
	"log"
	"testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type DBSuite struct {
	suite.Suite
	st *app.State
}

func (s *DBSuite) SetupSuite() {
	var err error
	s.st, err = unit.State()
	if err != nil {
		log.Fatal(err.Error())
	}
}

func (s *DBSuite) TestEncrypted() {
	keyVersion, key, keyErr := s.st.VersionKey.GetCurrent()
	require.NoError(s.T(), keyErr)
	displayName := safe.TrustedVarChar(security.RandString())
	email := safe.TrustedVarChar(security.RandString())
	org := models.NewID()
	password, passwordErr := security.DerivePassword(security.RandString(), s.st.Argon2Config)
	require.NoError(s.T(), passwordErr)
	u, uErr := user.New(displayName, email, org, *password)
	require.NoError(s.T(), uErr)
	apiSecret := u.APISecret
	encryptErr := u.Encrypt(key, keyVersion)
	require.NoError(s.T(), encryptErr)

	// Capture an encrypted field and then re-encrypt to
	// ensure that Encrypt is idempotent.
	encryptedDisplayName := u.DisplayName
	encryptErr = u.Encrypt(key, keyVersion)
	require.NoError(s.T(), encryptErr)
	require.Equal(s.T(), encryptedDisplayName.String(), u.DisplayName.String())

	decryptErr := u.Decrypt(s.st.VersionKey)
	require.NoError(s.T(), decryptErr)
	require.Equal(s.T(), apiSecret.String(), u.APISecret.String())
	require.Equal(s.T(), displayName.String(), u.DisplayName.String())
	require.Equal(s.T(), email.String(), u.Email.String())

	// Decrypt again to show that Decrypt is idempotent.
	decryptErr = u.Decrypt(s.st.VersionKey)
	require.NoError(s.T(), decryptErr)
	require.Equal(s.T(), apiSecret.String(), u.APISecret.String())
	require.Equal(s.T(), displayName.String(), u.DisplayName.String())
	require.Equal(s.T(), email.String(), u.Email.String())
}

func (s *DBSuite) TestReadMiss() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	_, readErr := user.Read(context.Background(), conn.Conn(), s.st.VersionKey, models.NewID())
	require.Equal(s.T(), models.ErrNotFound, readErr)
}

func (s *DBSuite) TestInsertRead() {
	keyVersion, key, keyErr := s.st.VersionKey.GetCurrent()
	require.NoError(s.T(), keyErr)
	displayName := safe.TrustedVarChar(security.RandString())
	email := safe.TrustedVarChar(security.RandString())
	org := models.NewID()
	password, passwordErr := security.DerivePassword(security.RandString(), s.st.Argon2Config)
	require.NoError(s.T(), passwordErr)

	u, uErr := user.New(displayName, email, org, *password)
	require.NoError(s.T(), uErr)
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	require.NoError(s.T(), u.Insert(
		context.Background(),
		conn.Conn(),
		keyVersion,
		key,
	))

	// duplicate
	require.Equal(s.T(), models.ErrConflict,
		u.Insert(
			context.Background(),
			conn.Conn(),
			keyVersion,
			key,
		))

	// read
	uRead, readErr := user.Read(context.Background(), conn.Conn(), s.st.VersionKey, u.ID)
	require.NoError(s.T(), readErr)
	require.Equal(s.T(), u.ID, uRead.ID)
	require.Equal(s.T(), u.APISecret, uRead.APISecret)
	require.Equal(s.T(), u.APISecretDigest, uRead.APISecretDigest)
	require.Equal(s.T(), u.DisplayName, uRead.DisplayName)
	require.Equal(s.T(), u.DisplayNameDigest, uRead.DisplayNameDigest)
	require.Equal(s.T(), u.Email, uRead.Email)
	require.Equal(s.T(), u.EmailDigest, uRead.EmailDigest)
	// u does not have KeyVersion set yet
	require.NotEqual(s.T(), u.KeyVersion, uRead.KeyVersion)
	require.Equal(s.T(), u.Org, uRead.Org)
	require.Equal(s.T(), u.Password, uRead.Password) // both derived already
	require.NotEqual(s.T(), u.Meta.Ctime, uRead.Meta.Ctime)
	require.NotEqual(s.T(), u.Meta.Mtime, uRead.Meta.Mtime)
	require.Equal(s.T(), u.Meta.SchemaVersion, uRead.Meta.SchemaVersion)
	require.NotEqual(s.T(), u.Meta.Signature, uRead.Meta.Signature)
	require.Equal(s.T(), u.Meta.Role, uRead.Meta.Role)
	require.Equal(s.T(), u.Meta.Status, uRead.Meta.Status)
}

func (s *DBSuite) TestCreate() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	orgName := safe.TrustedVarChar(security.RandString())
	ownerDisplayName := safe.TrustedVarChar(security.RandString())
	ownerEmail := safe.TrustedVarChar(security.RandString())
	ownerPassword, ownerPasswordErr := security.DerivePassword(security.RandString(), s.st.Argon2Config)
	require.NoError(s.T(), ownerPasswordErr)

	o, _, orgCreateErr := org.Create(context.Background(),
		conn.Conn(),
		orgName,
		ownerDisplayName,
		ownerEmail,
		*ownerPassword,
		models.RoleTest,
		s.st.VersionKey)
	require.NoError(s.T(), orgCreateErr)

	displayName := safe.TrustedVarChar(security.RandString())
	email := safe.TrustedVarChar(security.RandString())
	password, passwordErr := security.DerivePassword(security.RandString(), s.st.Argon2Config)
	require.NoError(s.T(), passwordErr)

	u, uCreateErr := user.Create(context.Background(), conn.Conn(), displayName, email, o.ID, *password, s.st.VersionKey)
	require.NoError(s.T(), uCreateErr)
	require.Equal(s.T(), models.RoleTest, u.Meta.Role)
	require.Equal(s.T(), o.ID, u.Org)
}

func (s *DBSuite) TestCreateOrgMissing() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	displayName := safe.TrustedVarChar(security.RandString())
	email := safe.TrustedVarChar(security.RandString())
	password, passwordErr := security.DerivePassword(security.RandString(), s.st.Argon2Config)
	require.NoError(s.T(), passwordErr)

	_, uCreateErr := user.Create(context.Background(), conn.Conn(), displayName, email, models.NewID(), *password, s.st.VersionKey)
	require.Equal(s.T(), models.ErrNotFound, uCreateErr)
}

func (s *DBSuite) TestCreateOrgInactive() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	orgName := safe.TrustedVarChar(security.RandString())
	ownerDisplayName := safe.TrustedVarChar(security.RandString())
	ownerEmail := safe.TrustedVarChar(security.RandString())
	ownerPassword, ownerPasswordErr := security.DerivePassword(security.RandString(), s.st.Argon2Config)
	require.NoError(s.T(), ownerPasswordErr)

	o, _, orgCreateErr := org.Create(context.Background(),
		conn.Conn(),
		orgName,
		ownerDisplayName,
		ownerEmail,
		*ownerPassword,
		models.RoleTest,
		s.st.VersionKey)
	require.NoError(s.T(), orgCreateErr)

	statusUpdateErr := models.Update(context.Background(),
		conn.Conn(),
		"orgs",
		o.ID,
		"status",
		models.StatusInactive)
	require.NoError(s.T(), statusUpdateErr)

	displayName := safe.TrustedVarChar(security.RandString())
	email := safe.TrustedVarChar(security.RandString())
	password, passwordErr := security.DerivePassword(security.RandString(), s.st.Argon2Config)
	require.NoError(s.T(), passwordErr)

	_, uCreateErr := user.Create(context.Background(), conn.Conn(), displayName, email, o.ID, *password, s.st.VersionKey)
	require.Equal(s.T(), models.ErrRelatedOrg, uCreateErr)
}

func (s *DBSuite) TestReEncrypt() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	_, _, u, createErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)

	keyVersion, _, keyErr := s.st.VersionKey.GetCurrent()
	require.NoError(s.T(), keyErr)
	reEncryptErr := u.ReEncrypt(context.Background(), conn.Conn(), keyVersion, s.st.VersionKey)
	require.NoError(s.T(), reEncryptErr)

	uRead, readErr := user.Read(context.Background(), conn.Conn(), s.st.VersionKey, u.ID)
	require.NoError(s.T(), readErr)
	require.Equal(s.T(), u.APISecret.String(), uRead.APISecret.String())
	require.Equal(s.T(), u.DisplayName.String(), uRead.DisplayName.String())
	require.Equal(s.T(), u.Email.String(), uRead.Email.String())
}

func (s *DBSuite) TestUpdateAPISecret() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	_, _, u, createErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)

	priorAPISecret := u.APISecret
	priorMeta := u.Meta

	apiSecretUpdateErr := u.UpdateAPISecret(context.Background(),
		conn.Conn(),
		s.st.VersionKey)
	require.NoError(s.T(), apiSecretUpdateErr)

	require.NotEqual(s.T(), priorAPISecret, u.APISecret)
	require.NotEqual(s.T(), priorMeta.Signature, u.Meta.Signature)
}

func (s *DBSuite) TestUpdateDisplayName() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	_, _, u, createErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)

	priorMeta := u.Meta

	newDisplayName := safe.TrustedVarChar(security.RandString())
	newDisplayNameDigest := security.EncodedSHA256(newDisplayName.String())

	displayNameUpdateErr := u.UpdateDisplayName(context.Background(),
		conn.Conn(),
		s.st.VersionKey,
		newDisplayName)
	require.NoError(s.T(), displayNameUpdateErr)

	require.Equal(s.T(), newDisplayName, u.DisplayName)
	require.Equal(s.T(), newDisplayNameDigest, u.DisplayNameDigest)
	require.NotEqual(s.T(), priorMeta.Signature, u.Meta.Signature)
}

func (s *DBSuite) TestUpdatePassword() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	_, _, u, createErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)

	priorMeta := u.Meta

	newPassword, newPasswordErr := security.DerivePassword(security.RandString(), s.st.Argon2Config)
	require.NoError(s.T(), newPasswordErr)

	passwordUpdateErr := u.UpdatePassword(context.Background(),
		conn.Conn(),
		s.st.VersionKey,
		*newPassword)
	require.NoError(s.T(), passwordUpdateErr)

	require.Equal(s.T(), newPassword.String(), u.Password.String())
	require.NotEqual(s.T(), priorMeta.Signature, u.Meta.Signature)
}

func (s *DBSuite) TestUpdateStatus() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	_, _, u, createErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)

	priorMeta := u.Meta

	statusUpdateErr := u.UpdateStatus(context.Background(),
		conn.Conn(),
		s.st.VersionKey,
		models.StatusInactive)
	require.NoError(s.T(), statusUpdateErr)

	require.Equal(s.T(), models.StatusInactive, u.Meta.Status)
	require.NotEqual(s.T(), priorMeta.Signature, u.Meta.Signature)
}

func (s *DBSuite) TearDownSuite() {
	_ = s.st.Close()
}

func TestDBSuite(t *testing.T) {
	suite.Run(t, new(DBSuite))
}
