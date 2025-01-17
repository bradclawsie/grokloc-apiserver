package testing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	testing_ "testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
)

func TestGet(t *testing_.T) {
	t.Run("AsRoot", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()
		_, _, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, oErr)
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + regularUser.ID.String())
		require.NoError(t, urlErr)

		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// get response body (json serialized user)
		decoder := json.NewDecoder(resp.Body)
		decoder.DisallowUnknownFields()
		var usr user.User
		dcErr := decoder.Decode(&usr)
		require.NoError(t, dcErr)

		require.Equal(t, regularUser.ID, usr.ID)
		require.Equal(t, regularUser.Org, usr.Org)
		require.NotEqual(t, regularUser.Password, usr.Password)
		require.Equal(t, regularUser.APISecret, usr.APISecret)
		require.Equal(t, regularUser.APISecretDigest, usr.APISecretDigest)
		require.Equal(t, regularUser.DisplayName, usr.DisplayName)
		require.Equal(t, regularUser.DisplayNameDigest, usr.DisplayNameDigest)
		require.Equal(t, regularUser.Email, usr.Email)
		require.Equal(t, regularUser.EmailDigest, usr.EmailDigest)
		require.Equal(t, regularUser.Meta, usr.Meta)
	})

	t.Run("AsOrgOwner", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + regularUser.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// get response body (json serialized user)
		decoder := json.NewDecoder(resp.Body)
		decoder.DisallowUnknownFields()
		var usr user.User
		dcErr := decoder.Decode(&usr)
		require.NoError(t, dcErr)

		require.Equal(t, regularUser.ID, usr.ID)
		require.Equal(t, regularUser.Org, usr.Org)
		require.NotEqual(t, regularUser.Password, usr.Password)
		require.Equal(t, regularUser.APISecret, usr.APISecret)
		require.Equal(t, regularUser.APISecretDigest, usr.APISecretDigest)
		require.Equal(t, regularUser.DisplayName, usr.DisplayName)
		require.Equal(t, regularUser.DisplayNameDigest, usr.DisplayNameDigest)
		require.Equal(t, regularUser.Email, usr.Email)
		require.Equal(t, regularUser.EmailDigest, usr.EmailDigest)
		require.Equal(t, regularUser.Meta, usr.Meta)

		// try to get a user (root) that org owner has no permission to access
		u, urlErr = url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + st.Root.ID.String())
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
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + regularUser.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// get response body (json serialized user)
		decoder := json.NewDecoder(resp.Body)
		decoder.DisallowUnknownFields()
		var usr user.User
		dcErr := decoder.Decode(&usr)
		require.NoError(t, dcErr)

		require.Equal(t, regularUser.ID, usr.ID)
		require.Equal(t, regularUser.Org, usr.Org)
		require.NotEqual(t, regularUser.Password, usr.Password)
		require.Equal(t, regularUser.APISecret, usr.APISecret)
		require.Equal(t, regularUser.APISecretDigest, usr.APISecretDigest)
		require.Equal(t, regularUser.DisplayName, usr.DisplayName)
		require.Equal(t, regularUser.DisplayNameDigest, usr.DisplayNameDigest)
		require.Equal(t, regularUser.Email, usr.Email)
		require.Equal(t, regularUser.EmailDigest, usr.EmailDigest)
		require.Equal(t, regularUser.Meta, usr.Meta)

		// try to get a user (root) that regular user has no permission to access
		u, urlErr = url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + st.Root.ID.String())
		require.NoError(t, urlErr)
		req, reqErr = http.NewRequest(http.MethodGet, u.String(), nil)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		require.NoError(t, reqErr)
		resp, getErr = c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)

		// create another user in the same org, try to read it
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()
		displayName := safe.TrustedVarChar(security.RandString())
		email := safe.TrustedVarChar(security.RandString())
		password, passwordErr := security.DerivePassword(security.RandString(), st.Argon2Config)
		require.NoError(t, passwordErr)
		peerUser, createErr := user.Create(context.Background(), conn.Conn(), displayName, email, o.ID, *password, st.VersionKey)
		require.NoError(t, createErr)
		u, urlErr = url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + peerUser.ID.String())
		require.NoError(t, urlErr)
		req, reqErr = http.NewRequest(http.MethodGet, u.String(), nil)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		require.NoError(t, reqErr)
		resp, getErr = c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("NotFound", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + models.NewID().String())
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
