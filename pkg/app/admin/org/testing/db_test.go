// Package testing breaks an import loop for org
package testing

import (
	"context"
	"log"
	"testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
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
		log.Fatalf(err.Error())
	}
}

func (s *DBSuite) TearDownSuite() {
	_ = s.st.Close()
}

func (s *DBSuite) TestInsertRead() {
	o := &org.Org{}
	o.ID = models.NewID()
	o.Name = safe.TrustedVarChar(security.RandString())
	o.Owner = models.NewID()
	o.Meta.Role = models.RoleTest
	o.Meta.Status = models.StatusActive

	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	require.NoError(s.T(), o.Insert(context.Background(), conn.Conn()))

	// duplicate
	require.Equal(s.T(), models.ErrConflict, o.Insert(context.Background(), conn.Conn()))

	// read
	oRead, readErr := org.Read(context.Background(), conn.Conn(), o.ID)
	require.NoError(s.T(), readErr)
	require.Equal(s.T(), o.ID, oRead.ID)
	require.Equal(s.T(), o.Owner, oRead.Owner)
	require.Equal(s.T(), o.Meta.Role, oRead.Meta.Role)
	require.Equal(s.T(), o.Meta.Status, oRead.Meta.Status)
	require.Equal(s.T(), o.Meta.SchemaVersion, oRead.Meta.SchemaVersion)
	require.NotEqual(s.T(), o.Meta.Ctime, oRead.Meta.Ctime)
	require.NotEqual(s.T(), o.Meta.Mtime, oRead.Meta.Mtime)
	require.NotEqual(s.T(), o.Meta.Signature, oRead.Meta.Signature)
}

func (s *DBSuite) TestReadMissing() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	_, readErr := org.Read(context.Background(), conn.Conn(), models.NewID())
	require.Equal(s.T(), models.ErrNotFound, readErr)
}

func (s *DBSuite) TestCreate() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	name := safe.TrustedVarChar(security.RandString())
	ownerDisplayName := safe.TrustedVarChar(security.RandString())
	ownerEmail := safe.TrustedVarChar(security.RandString())
	ownerPassword, passwordErr := security.DerivePassword(security.RandString(), s.st.Argon2Config)
	require.NoError(s.T(), passwordErr)

	org, owner, createErr := org.Create(context.Background(),
		conn.Conn(),
		name,
		ownerDisplayName,
		ownerEmail,
		*ownerPassword,
		models.RoleTest,
		s.st.VersionKey)
	require.NoError(s.T(), createErr)
	require.Equal(s.T(), models.RoleTest, org.Meta.Role)
	require.Equal(s.T(), org.Meta.Role, owner.Meta.Role)
	require.Equal(s.T(), org.Owner, owner.ID)
	require.Equal(s.T(), owner.Org, org.ID)
	require.Equal(s.T(), name, org.Name)
	// DisplayName and Email are decrypted from Read(...)
	require.Equal(s.T(), ownerDisplayName, owner.DisplayName)
	require.Equal(s.T(), ownerEmail, owner.Email)
	require.Equal(s.T(), *ownerPassword, owner.Password)
}

func (s *DBSuite) TestUpdateStatus() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	o, _, _, createErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)

	priorMeta := o.Meta

	statusUpdateErr := o.UpdateStatus(context.Background(), conn.Conn(), models.StatusInactive)
	require.NoError(s.T(), statusUpdateErr)
	require.NotEqual(s.T(), priorMeta.Signature, o.Meta.Signature)
}

func (s *DBSuite) TestUpdateOwner() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	o, _, u, createErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)

	// try updating o owner to owner that doesn't exist
	ownerUpdateErr := o.UpdateOwner(context.Background(), conn.Conn(), models.NewID())
	require.Equal(s.T(), models.ErrRelatedUser, ownerUpdateErr)

	// change u status to unconfirmed for the next test
	statusUpdateErr := u.UpdateStatus(context.Background(),
		conn.Conn(),
		s.st.VersionKey,
		models.StatusInactive,
	)
	require.NoError(s.T(), statusUpdateErr)

	// u is a non-owner user in o, try making it new owner
	// u has status unconfirmed as of update above
	ownerUpdateErr = o.UpdateOwner(context.Background(), conn.Conn(), u.ID)
	require.Equal(s.T(), models.ErrRelatedUser, ownerUpdateErr)

	// update u status to active
	statusUpdateErr = u.UpdateStatus(context.Background(),
		conn.Conn(),
		s.st.VersionKey,
		models.StatusActive,
	)
	require.NoError(s.T(), statusUpdateErr)
	ownerUpdateErr = o.UpdateOwner(context.Background(), conn.Conn(), u.ID)
	require.NoError(s.T(), ownerUpdateErr)
	require.Equal(s.T(), o.Owner, u.ID)

	// create a new "other" org, try to make u the owner of it
	other, _, _, otherErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), otherErr)

	// u is not a user in other, so this fails
	ownerUpdateErr = other.UpdateOwner(context.Background(), conn.Conn(), u.ID)
	require.Equal(s.T(), models.ErrRelatedUser, ownerUpdateErr)
}

func TestDBSuite(t *testing.T) {
	suite.Run(t, new(DBSuite))
}
