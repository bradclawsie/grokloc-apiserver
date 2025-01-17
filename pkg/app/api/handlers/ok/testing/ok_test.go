package testing

import (
	"log"
	"net/http"
	"net/http/httptest"
	testing_ "testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api"
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
	rtr := api.NewRouter(st)
	srv = httptest.NewServer(rtr)
}

func TestOKHandler(t *testing_.T) {
	t.Parallel()
	t.Run("Get", func(t *testing_.T) {
		resp, respErr := http.Get(srv.URL + "/ok")
		require.NoError(t, respErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
