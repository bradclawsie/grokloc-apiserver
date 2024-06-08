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
	"github.com/grokloc/grokloc-go/pkg/app"
	"github.com/grokloc/grokloc-go/pkg/app/admin/org"
	"github.com/grokloc/grokloc-go/pkg/app/admin/user"
	"github.com/grokloc/grokloc-go/pkg/app/api/handlers/token"
	"github.com/grokloc/grokloc-go/pkg/app/api/middlewares/auth/withtoken"
	"github.com/grokloc/grokloc-go/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-go/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-go/pkg/app/jwt"
	"github.com/grokloc/grokloc-go/pkg/app/models"
	"github.com/grokloc/grokloc-go/pkg/app/state/unit"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	app_testing "github.com/grokloc/grokloc-go/pkg/app/testing"
)

type WithTokenSuite struct {
	suite.Suite
	st    *app.State
	srv   *httptest.Server
	Org   *org.Org
	Owner *user.User
	User  *user.User
}

type message struct {
	RequestID string             `json:"request_id"`
	OrgID     models.ID          `json:"org_id"`
	UserID    models.ID          `json:"user_id"`
	Auth      withuser.AuthLevel `json:"auth"`
}

func (s *WithTokenSuite) SetupSuite() {
	st, stErr := unit.State()
	require.NoError(s.T(), stErr)
	s.st = st
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	org, owner, regularUser, createErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)
	s.Org = org
	s.Owner = owner
	s.User = regularUser
	rtr := chi.NewRouter()
	rtr.Use(request.Middleware(st))

	rtr.Route("/token", func(rtr chi.Router) {
		rtr.Use(withuser.Middleware(st))
		rtr.Post("/", token.Post(st))
	})

	rtr.Route("/message", func(rtr chi.Router) {
		rtr.Use(withuser.Middleware(st))
		rtr.Use(withtoken.Middleware(st))
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
	})

	s.srv = httptest.NewServer(rtr)
}

func (s *WithTokenSuite) TestValidToken() {
	// make token request
	u, urlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), urlErr)
	tokenRequest := jwt.EncodeTokenRequest(s.User.ID, s.User.APISecret.String())
	req0 := http.Request{
		URL:    u,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.User.ID.String()},
			app.TokenRequestHeader: {tokenRequest},
		},
	}
	client := http.Client{}
	resp, postErr := client.Do(&req0)
	require.NoError(s.T(), postErr)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var m token.JSONToken
	umErr := json.Unmarshal(body, &m)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), m.Token)
	// m.Token is Authorization header value
	_, decodeErr := jwt.Decode(m.Token, s.st.SigningKey)
	require.NoError(s.T(), decodeErr)

	// GET /message with Authorization header set
	u, urlErr = url.Parse(s.srv.URL + "/message")
	require.NoError(s.T(), urlErr)
	req1 := http.Request{
		URL:    u,
		Method: http.MethodGet,
		Header: map[string][]string{
			app.IDHeader:            {s.User.ID.String()},
			app.AuthorizationHeader: {jwt.SignedStringToHeaderValue(m.Token)},
		},
	}
	var getErr error
	resp, getErr = client.Do(&req1)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), resp.StatusCode, http.StatusOK)
	defer resp.Body.Close()
	_, readErr = io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)

	// try not adding the authorization header at all
	req2 := http.Request{
		URL:    u,
		Method: http.MethodGet,
		Header: map[string][]string{
			app.IDHeader: {s.User.ID.String()},
		},
	}
	resp, getErr = client.Do(&req2)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), resp.StatusCode, http.StatusBadRequest)

	// try mixing the token with a different ID header
	req3 := http.Request{
		URL:    u,
		Method: http.MethodGet,
		Header: map[string][]string{
			// s.Owner id
			app.IDHeader: {s.Owner.ID.String()},
			// s.User token
			app.AuthorizationHeader: {jwt.SignedStringToHeaderValue(m.Token)},
		},
	}
	resp, getErr = client.Do(&req3)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), resp.StatusCode, http.StatusBadRequest)
}

func (s *WithTokenSuite) TearDownSuite() {
	s.srv.Close()
}

func TestWithTokenSuite(t *testing.T) {
	suite.Run(t, new(WithTokenSuite))
}
