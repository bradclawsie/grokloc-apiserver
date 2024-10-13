package testing

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app/api"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type OKSuite struct {
	suite.Suite
	srv *httptest.Server
}

func (s *OKSuite) SetupSuite() {
	st, stErr := unit.State()
	require.NoError(s.T(), stErr)
	rtr := api.NewRouter(st)
	s.srv = httptest.NewServer(rtr)
}

func (s *OKSuite) TestGet() {
	resp, respErr := http.Get(s.srv.URL + "/ok")
	require.NoError(s.T(), respErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *OKSuite) TearDownSuite() {
	s.srv.Close()
}

func TestOKSuite(t *testing.T) {
	suite.Run(t, new(OKSuite))
}
