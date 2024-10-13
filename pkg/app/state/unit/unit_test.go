package unit

import (
	"context"
	"log"
	"testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type UnitSuite struct {
	suite.Suite
	st *app.State
}

func (s *UnitSuite) SetupSuite() {
	var err error
	s.st, err = State()
	if err != nil {
		log.Fatal(err.Error())
	}
}

func (s *UnitSuite) TearDownSuite() {
	_ = s.st.Close()
}

func (s *UnitSuite) TestConn() {
	ctx := context.Background()

	conn, connErr := s.st.Master.Acquire(ctx)
	require.NoError(s.T(), connErr)
	defer conn.Release()

	var count int32
	selectErr := conn.QueryRow(ctx, `select count(*) from orgs`).Scan(&count)
	require.NoError(s.T(), selectErr)

	require.True(s.T(), true)
}

func TestUnitSuite(t *testing.T) {
	suite.Run(t, new(UnitSuite))
}
