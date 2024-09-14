package audit

import (
	"context"
	"log"
	"testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/audit"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type AuditSuite struct {
	suite.Suite
	st *app.State
}

func (s *AuditSuite) SetupSuite() {
	var err error
	s.st, err = unit.State()
	if err != nil {
		log.Fatal(err.Error())
	}
}

func (s *AuditSuite) TearDownSuite() {
	_ = s.st.Close()
}

func (s *AuditSuite) TestInsert() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	err := audit.Insert(
		context.Background(),
		conn.Conn(),
		audit.UserInsert,
		security.RandString(),
		models.NewID(),
	)

	require.Nil(s.T(), err)
}

func TestAuditSuite(t *testing.T) {
	suite.Run(t, new(AuditSuite))
}
