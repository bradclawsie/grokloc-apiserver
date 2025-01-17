package testing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	testing_ "testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/token"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/stretchr/testify/require"
)

func TestDelete(t *testing_.T) {
	t.Run("AsRoot", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()
		// create a user to DELETE to
		_, _, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, oErr)

		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + regularUser.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodDelete, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, deleteErr := c.Do(req)
		require.NoError(t, deleteErr)
		require.Equal(t, http.StatusNoContent, resp.StatusCode)

		// read out to confirm
		uRead, uErr := user.Read(context.Background(), conn.Conn(), st.VersionKey, regularUser.ID)
		require.NoError(t, uErr)
		require.Equal(t, regularUser.ID, uRead.ID)
		require.Equal(t, models.StatusInactive, uRead.Meta.Status)
	})

	t.Run("AsOrgOwner", func(t *testing_.T) {
		t.Parallel()
		// make a new org owner with a regular user to delete
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()
		_, owner, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, oErr)
		tokenReqUrl, tokenReqUrlErr := url.Parse(srv.URL + "/token")
		require.NoError(t, tokenReqUrlErr)
		ownerTokenRequest := jwt.EncodeTokenRequest(owner.ID, owner.APISecret.String())
		ownerReq := http.Request{
			URL:    tokenReqUrl,
			Method: http.MethodPost,
			Header: map[string][]string{
				app.IDHeader:           {owner.ID.String()},
				app.TokenRequestHeader: {ownerTokenRequest},
			},
		}
		resp, postErr := c.Do(&ownerReq)
		require.NoError(t, postErr)
		require.Equal(t, resp.StatusCode, http.StatusOK)
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		require.NoError(t, readErr)
		var ownerTok token.JSONToken
		umErr := json.Unmarshal(body, &ownerTok)
		require.NoError(t, umErr)
		require.NotEmpty(t, ownerTok.Token)

		// try to set to inactive
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + regularUser.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodDelete, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, deleteErr := c.Do(req)
		require.NoError(t, deleteErr)
		require.Equal(t, http.StatusNoContent, resp.StatusCode)

		// read out to confirm
		uRead, uErr := user.Read(context.Background(), conn.Conn(), st.VersionKey, regularUser.ID)
		require.NoError(t, uErr)
		require.Equal(t, regularUser.ID, uRead.ID)
		require.Equal(t, models.StatusInactive, uRead.Meta.Status)
	})

	t.Run("AsRegularUser", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + regularUser.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodDelete, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		resp, deleteErr := c.Do(req)
		require.NoError(t, deleteErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("NotFound", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + models.NewID().String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodDelete, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, deleteErr := c.Do(req)
		require.NoError(t, deleteErr)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}
