package client

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	testing_ "testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/stretchr/testify/require"
)

var (
	srv                                           *httptest.Server
	st                                            *app.State
	o                                             *org.Org
	orgOwner, regularUser                         *user.User
	rootClient, orgOwnerClient, regularUserClient *Client
)

func TestMain(m *testing_.M) {
	var stErr error
	st, stErr = unit.State()
	if stErr != nil {
		log.Fatal(stErr.Error())
	}

	rtr := api.NewRouter(st)
	srv = httptest.NewServer(rtr)
	var clientErr error
	httpClient := http.Client{}
	rootClient, clientErr = New(
		st.Root.ID.String(),
		st.Root.APISecret.String(),
		srv.URL,
		st.APIVersion,
		&httpClient,
	)
	if clientErr != nil {
		log.Fatal(clientErr.Error())
	}

	conn, connErr := st.Master.Acquire(context.Background())
	if connErr != nil {
		log.Fatal(connErr.Error())
	}
	defer conn.Release()
	var oErr error
	o, orgOwner, regularUser, oErr = app_testing.TestOrgAndUser(conn.Conn(), st)
	if oErr != nil {
		log.Fatal(oErr.Error())
	}

	orgOwnerClient, clientErr = New(
		orgOwner.ID.String(),
		orgOwner.APISecret.String(),
		srv.URL,
		st.APIVersion,
		&httpClient,
	)
	if clientErr != nil {
		log.Fatal(clientErr.Error())
	}

	regularUserClient, clientErr = New(
		regularUser.ID.String(),
		regularUser.APISecret.String(),
		srv.URL,
		st.APIVersion,
		&httpClient,
	)
	if clientErr != nil {
		log.Fatal(clientErr.Error())
	}

	m.Run()
}

func TestClient(t *testing_.T) {
	t.Run("OK", func(t *testing_.T) {
		t.Parallel()
		require.NoError(t, rootClient.OK())
		require.NoError(t, orgOwnerClient.OK())
		require.NoError(t, regularUserClient.OK())
	})

	t.Run("AuthOK", func(t *testing_.T) {
		t.Parallel()
		require.NoError(t, rootClient.AuthOK())
		require.NoError(t, orgOwnerClient.AuthOK())
		require.NoError(t, regularUserClient.AuthOK())
	})
}
