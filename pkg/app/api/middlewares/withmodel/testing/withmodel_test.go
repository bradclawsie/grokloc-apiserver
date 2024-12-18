package testing

import (
	"log"
	"net/http"
	"net/http/httptest"
	testing_ "testing"

	"github.com/go-chi/chi/v5"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	"github.com/stretchr/testify/require"
)

var (
	st  *app.State
	srv *httptest.Server
)

func TestMain(m *testing_.M) {
	var stErr error
	st, stErr = unit.State()
	if stErr != nil {
		log.Fatal(stErr.Error())
	}

	rtr := chi.NewRouter()
	rtr.Use(request.Middleware(st))
	rtr.Route("/org", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(org.LoadModel(st))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {
				_ = withmodel.GetModelWithOrg(r)
			})
		})
	})
	rtr.Route("/user", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(user.LoadModel(st))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {
				_ = withmodel.GetModelWithUser(r)
			})
		})
	})

	// this route uses an unsupported models.Kind
	rtr.Route("/none", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(withmodel.Middleware(st, models.KindNone))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {
				panic("middleware did not short circuit")
			})
		})
	})
	srv = httptest.NewServer(rtr)

	m.Run()
}

func TestWithModel(t *testing_.T) {
	client := http.Client{}

	t.Run("MalformedID", func(t *testing_.T) {
		t.Parallel()
		resp, respErr := client.Get(srv.URL + "/org/123456")
		require.NoError(t, respErr)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("GetOrg", func(t *testing_.T) {
		t.Parallel()
		resp, respErr := client.Get(srv.URL + "/org/" + st.Org.ID.String())
		require.NoError(t, respErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("OrgNotFound", func(t *testing_.T) {
		t.Parallel()
		resp, respErr := client.Get(srv.URL + "/org/" + models.NewID().String())
		require.NoError(t, respErr)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("GetUser", func(t *testing_.T) {
		t.Parallel()
		resp, respErr := client.Get(srv.URL + "/user/" + st.Root.ID.String())
		require.NoError(t, respErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("UserNotFound", func(t *testing_.T) {
		t.Parallel()
		resp, respErr := client.Get(srv.URL + "/user/" + models.NewID().String())
		require.NoError(t, respErr)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("FailingHandler", func(t *testing_.T) {
		t.Parallel()
		resp, respErr := client.Get(srv.URL + "/none/" + models.NewID().String())
		require.NoError(t, respErr)
		require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}
