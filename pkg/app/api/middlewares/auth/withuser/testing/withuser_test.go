package testing

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	testing_ "testing"

	"github.com/go-chi/chi/v5"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/stretchr/testify/require"
)

var (
	st          *app.State
	srv         *httptest.Server
	owner       *user.User
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
	_, owner, regularUser, createErr = app_testing.TestOrgAndUser(conn.Conn(), st)
	if createErr != nil {
		log.Fatal(createErr.Error())
	}

	rtr := chi.NewRouter()
	rtr.Use(request.Middleware(st))
	rtr.Use(withuser.Middleware(st))
	rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {})

	srv = httptest.NewServer(rtr)
}

func TestWithUser(t *testing_.T) {
	t.Run("RegularUser", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + "/")
		require.NoError(t, urlErr)
		req := http.Request{
			URL:    u,
			Method: http.MethodGet,
			Header: map[string][]string{
				app.IDHeader: {regularUser.ID.String()},
			},
		}
		client := http.Client{}
		resp, getErr := client.Do(&req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("OrgOwner", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + "/")
		require.NoError(t, urlErr)
		req := http.Request{
			URL:    u,
			Method: http.MethodGet,
			Header: map[string][]string{
				app.IDHeader: {owner.ID.String()},
			},
		}
		client := http.Client{}
		resp, getErr := client.Do(&req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("RootUser", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + "/")
		require.NoError(t, urlErr)
		req := http.Request{
			URL:    u,
			Method: http.MethodGet,
			Header: map[string][]string{
				app.IDHeader: {st.Root.ID.String()},
			},
		}
		client := http.Client{}
		resp, getErr := client.Do(&req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("MissingUser", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + "/")
		require.NoError(t, urlErr)
		req := http.Request{
			URL:    u,
			Method: http.MethodGet,
			Header: map[string][]string{
				app.IDHeader: {models.NewID().String()},
			},
		}
		client := http.Client{}
		resp, getErr := client.Do(&req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("InactiveUser", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		_, owner, _, createErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, createErr)
		updateErr := owner.UpdateStatus(context.Background(), conn.Conn(), st.VersionKey, models.StatusInactive)
		require.NoError(t, updateErr)

		u, urlErr := url.Parse(srv.URL + "/")
		require.NoError(t, urlErr)
		req := http.Request{
			URL:    u,
			Method: http.MethodGet,
			Header: map[string][]string{
				app.IDHeader: {owner.ID.String()},
			},
		}
		client := http.Client{}
		resp, getErr := client.Do(&req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("InactiveOrg", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		o, owner, _, createErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, createErr)
		updateErr := o.UpdateStatus(context.Background(), conn.Conn(), models.StatusInactive)
		require.NoError(t, updateErr)

		u, urlErr := url.Parse(srv.URL + "/")
		require.NoError(t, urlErr)
		req := http.Request{
			URL:    u,
			Method: http.MethodGet,
			Header: map[string][]string{
				app.IDHeader: {owner.ID.String()},
			},
		}
		client := http.Client{}
		resp, getErr := client.Do(&req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}
