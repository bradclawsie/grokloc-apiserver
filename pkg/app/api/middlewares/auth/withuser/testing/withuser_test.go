package testing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type WithUserSuite struct {
	suite.Suite
	st      *app.State
	srv     *httptest.Server
	OrgID   models.ID
	OwnerID models.ID
	UserID  models.ID
}

type message struct {
	RequestID string             `json:"request_id"`
	OrgID     models.ID          `json:"org_id"`
	UserID    models.ID          `json:"user_id"`
	Auth      withuser.AuthLevel `json:"auth"`
}

func (s *WithUserSuite) SetupSuite() {
	st, stErr := unit.State()
	require.NoError(s.T(), stErr)
	s.st = st
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	org, owner, regularUser, createErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)
	s.OrgID = org.ID
	s.OwnerID = owner.ID
	s.UserID = regularUser.ID
	rtr := chi.NewRouter()

	rtr.Use(request.Middleware(st))
	rtr.Use(withuser.Middleware(st))
	rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {
		var m message
		m.RequestID = request.GetID(r)
		o := withuser.GetOrg(r)
		m.OrgID = o.ID
		u := withuser.GetUser(r)
		m.UserID = u.ID
		a := withuser.GetAuth(r)
		m.Auth = a
		bs, err := json.Marshal(m)
		if err != nil {
			panic(err.Error())
		}
		_, writeErr := w.Write(bs)
		if writeErr != nil {
			panic(writeErr.Error())
		}
	})

	s.srv = httptest.NewServer(rtr)
}

func (s *WithUserSuite) TestWithUser() {
	u, urlErr := url.Parse(s.srv.URL + "/")
	require.NoError(s.T(), urlErr)
	req := http.Request{
		URL:    u,
		Method: http.MethodGet,
		Header: map[string][]string{
			app.IDHeader: {s.UserID.String()},
		},
	}
	client := http.Client{}
	resp, getErr := client.Do(&req)
	require.NoError(s.T(), getErr)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var m message
	umErr := json.Unmarshal(body, &m)
	require.NoError(s.T(), umErr)
	require.Equal(s.T(), s.OrgID, m.OrgID)
	require.Equal(s.T(), s.UserID, m.UserID)
	require.Equal(s.T(), withuser.AuthUser, m.Auth)
}

func (s *WithUserSuite) TestWithUserOrgOwner() {
	u, urlErr := url.Parse(s.srv.URL + "/")
	require.NoError(s.T(), urlErr)
	req := http.Request{
		URL:    u,
		Method: http.MethodGet,
		Header: map[string][]string{
			app.IDHeader: {s.OwnerID.String()},
		},
	}
	client := http.Client{}
	resp, getErr := client.Do(&req)
	require.NoError(s.T(), getErr)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var m message
	umErr := json.Unmarshal(body, &m)
	require.NoError(s.T(), umErr)
	require.Equal(s.T(), s.OrgID, m.OrgID)
	require.Equal(s.T(), s.OwnerID, m.UserID)
	require.Equal(s.T(), withuser.AuthOrg, m.Auth)
}

func (s *WithUserSuite) TestWithUserRootUser() {
	u, urlErr := url.Parse(s.srv.URL + "/")
	require.NoError(s.T(), urlErr)
	req := http.Request{
		URL:    u,
		Method: http.MethodGet,
		Header: map[string][]string{
			app.IDHeader: {s.st.Root.ID.String()},
		},
	}
	client := http.Client{}
	resp, getErr := client.Do(&req)
	require.NoError(s.T(), getErr)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var m message
	umErr := json.Unmarshal(body, &m)
	require.NoError(s.T(), umErr)
	require.Equal(s.T(), s.st.Org.ID, m.OrgID)
	require.Equal(s.T(), s.st.Root.ID, m.UserID)
	require.Equal(s.T(), withuser.AuthRoot, m.Auth)
}

func (s *WithUserSuite) TestWithUserMissingUser() {
	u, urlErr := url.Parse(s.srv.URL + "/")
	require.NoError(s.T(), urlErr)
	req := http.Request{
		URL:    u,
		Method: http.MethodGet,
		Header: map[string][]string{
			app.IDHeader: {models.NewID().String()},
		},
	}
	client := http.Client{}
	resp, getErr := client.Do(&req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusNotFound, resp.StatusCode)
}

func (s *WithUserSuite) TestWithUserInactiveUser() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	_, owner, _, createErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)
	updateErr := owner.UpdateStatus(context.Background(), conn.Conn(), s.st.VersionKey, models.StatusInactive)
	require.NoError(s.T(), updateErr)

	u, urlErr := url.Parse(s.srv.URL + "/")
	require.NoError(s.T(), urlErr)
	req := http.Request{
		URL:    u,
		Method: http.MethodGet,
		Header: map[string][]string{
			app.IDHeader: {owner.ID.String()},
		},
	}
	client := http.Client{}
	resp, getErr := client.Do(&req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)
}

func (s *WithUserSuite) TestWithUserInactiveOrg() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	org, owner, _, createErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)
	updateErr := org.UpdateStatus(context.Background(), conn.Conn(), models.StatusInactive)
	require.NoError(s.T(), updateErr)

	u, urlErr := url.Parse(s.srv.URL + "/")
	require.NoError(s.T(), urlErr)
	req := http.Request{
		URL:    u,
		Method: http.MethodGet,
		Header: map[string][]string{
			app.IDHeader: {owner.ID.String()},
		},
	}
	client := http.Client{}
	resp, getErr := client.Do(&req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)
}

func (s *WithUserSuite) TearDownSuite() {
	s.srv.Close()
}

func TestWithUserSuite(t *testing.T) {
	suite.Run(t, new(WithUserSuite))
}
