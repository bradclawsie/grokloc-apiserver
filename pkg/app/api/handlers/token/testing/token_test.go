package testing

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	testing_ "testing"

	"github.com/go-chi/chi/v5"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/token"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/stretchr/testify/require"
)

var (
	st          *app.State
	srv         *httptest.Server
	regularUser *user.User
)

func TestMain(m *testing_.M) {
	var stErr error
	st, stErr = unit.State()
	if stErr != nil {
		log.Fatal(stErr.Error())
	}

	conn, connErr := st.Master.Acquire(context.Background())
	if connErr != nil {
		log.Fatal(connErr.Error())
	}
	defer conn.Release()

	var createErr error
	_, regularUser, _, createErr = app_testing.TestOrgAndUser(conn.Conn(), st)
	if createErr != nil {
		log.Fatal(createErr.Error())
	}
	rtr := chi.NewRouter()
	rtr.Use(request.Middleware(st))
	rtr.Use(withuser.Middleware(st))
	rtr.Post("/", token.Post(st))
	srv = httptest.NewServer(rtr)
}

func TestToken(t *testing_.T) {
	t.Run("Token", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + "/")
		require.NoError(t, urlErr)
		tokenRequest := jwt.EncodeTokenRequest(regularUser.ID, regularUser.APISecret.String())
		req := http.Request{
			URL:    u,
			Method: http.MethodPost,
			Header: map[string][]string{
				app.IDHeader:           {regularUser.ID.String()},
				app.TokenRequestHeader: {tokenRequest},
			},
		}
		client := http.Client{}
		resp, postErr := client.Do(&req)
		require.NoError(t, postErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		require.NoError(t, readErr)
		var m token.JSONToken
		umErr := json.Unmarshal(body, &m)
		require.NoError(t, umErr)
		require.NotEmpty(t, m.Token)
		_, decodeErr := jwt.Decode(m.Token, st.SigningKey)
		require.NoError(t, decodeErr)
	})

	t.Run("MissingTokenRequest", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + "/")
		require.NoError(t, urlErr)
		req := http.Request{
			URL:    u,
			Method: http.MethodPost,
			Header: map[string][]string{
				app.IDHeader: {regularUser.ID.String()},
			},
		}
		client := http.Client{}
		resp, postErr := client.Do(&req)
		require.NoError(t, postErr)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("BadRequestToken", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + "/")
		require.NoError(t, urlErr)
		// make new, random api secret that won't match
		tokenRequest := jwt.EncodeTokenRequest(regularUser.ID, models.NewID().String())
		req := http.Request{
			URL:    u,
			Method: http.MethodPost,
			Header: map[string][]string{
				app.IDHeader:           {regularUser.ID.String()},
				app.TokenRequestHeader: {tokenRequest},
			},
		}
		client := http.Client{}
		resp, postErr := client.Do(&req)
		require.NoError(t, postErr)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}
