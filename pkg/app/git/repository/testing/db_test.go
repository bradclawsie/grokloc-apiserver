package testing

import (
	"context"
	"log"
	"testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/git/repository"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
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

func (s *DBSuite) TestInsertRead() {
	r := &repository.Repository{}
	r.ID = models.NewID()
	r.Name = safe.TrustedVarChar(security.RandString())
	r.Org = models.NewID()
	r.Owner = models.NewID()
	r.Path = "/"
	r.Meta.Role = models.RoleTest
	r.Meta.Status = models.StatusActive

	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	require.NoError(s.T(), r.Insert(context.Background(), conn.Conn()))

	// duplicate
	require.Equal(s.T(), models.ErrConflict, r.Insert(context.Background(), conn.Conn()))

	// read
	rRead, readErr := repository.Read(context.Background(), conn.Conn(), r.ID)
	require.NoError(s.T(), readErr)
	require.Equal(s.T(), r.ID, rRead.ID)
	require.Equal(s.T(), r.Org, rRead.Org)
	require.Equal(s.T(), r.Owner, rRead.Owner)
	require.Equal(s.T(), r.Org, rRead.Org)
	require.Equal(s.T(), r.Path, rRead.Path)
	require.Equal(s.T(), r.Meta.Role, rRead.Meta.Role)
	require.Equal(s.T(), r.Meta.Status, rRead.Meta.Status)
	require.Equal(s.T(), r.Meta.SchemaVersion, rRead.Meta.SchemaVersion)
	require.NotEqual(s.T(), r.Meta.Ctime, rRead.Meta.Ctime)
	require.NotEqual(s.T(), r.Meta.Mtime, rRead.Meta.Mtime)
	require.NotEqual(s.T(), r.Meta.Signature, rRead.Meta.Signature)
}

func (s *DBSuite) TestReadMissing() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	_, readErr := repository.Read(context.Background(), conn.Conn(), models.NewID())
	require.Equal(s.T(), models.ErrNotFound, readErr)
}

func (s *DBSuite) TearDownSuite() {
	_ = s.st.Close()
}

func TestDBSuite(t *testing.T) {
	suite.Run(t, new(DBSuite))
}
