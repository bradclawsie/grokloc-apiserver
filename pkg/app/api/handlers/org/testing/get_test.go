package testing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	testing_ "testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/stretchr/testify/require"
)

func TestGet(t *testing_.T) {
	t.Run("AsRoot", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()
		// create an org to GET
		o, _, _, oErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, oErr)

		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org/" + o.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		// get response body (json serialized org)
		decoder := json.NewDecoder(resp.Body)
		decoder.DisallowUnknownFields()
		var oRead org.Org
		dcErr := decoder.Decode(&oRead)
		require.Equal(t, o.ID.String(), oRead.ID.String())
		require.NoError(t, dcErr)
	})

	t.Run("AsOrgOwner", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org/" + o.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		// get response body (json serialized org)
		decoder := json.NewDecoder(resp.Body)
		decoder.DisallowUnknownFields()
		oRead := org.Org{}
		dcErr := decoder.Decode(&oRead)
		require.Equal(t, o.ID.String(), oRead.ID.String())
		require.NoError(t, dcErr)

		// ty to get an org not owned by owner
		u, urlErr = url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org/" + st.Root.Org.String())
		require.NoError(t, urlErr)
		req, reqErr = http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, getErr = c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("AsRegularUser", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org/" + o.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("NotFound", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org/" + models.NewID().String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}
