package testing

import (
	"encoding/json"
	"net/http"
	"net/url"
	testing_ "testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/stretchr/testify/require"
)

func TestUsers(t *testing_.T) {
	t.Run("AsRoot", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org/" + o.ID.String() + "/users")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		decoder := json.NewDecoder(resp.Body)
		decoder.DisallowUnknownFields()
		var userIDs []models.ID
		dcErr := decoder.Decode(&userIDs)
		require.NoError(t, dcErr)
		require.Equal(t, 2, len(userIDs))
	})

	t.Run("AsOrgOwner", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org/" + o.ID.String() + "/users")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		decoder := json.NewDecoder(resp.Body)
		decoder.DisallowUnknownFields()
		var userIDs []models.ID
		dcErr := decoder.Decode(&userIDs)
		require.NoError(t, dcErr)
		require.Equal(t, 2, len(userIDs))
	})

	t.Run("AsRegularUser", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org/" + o.ID.String() + "/users")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("OrgNotFound", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org/" + models.NewID().String() + "/users")
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
