package testing

import (
	"bytes"
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
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
)

func TestPut(t *testing_.T) {
	t.Run("AsRoot", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()
		_, _, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, oErr)
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + regularUser.ID.String())
		require.NoError(t, urlErr)

		// update api secret
		previousAPISecret := regularUser.APISecret
		evUpdateAPISecret := user.UpdateAPISecretEvent{
			GenerateAPISecret: true,
		}
		bs, bsErr := json.Marshal(evUpdateAPISecret)
		require.NoError(t, bsErr)
		req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, putErr := c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// update display name
		newDisplayName := safe.TrustedVarChar(security.RandString())
		evUpdateDisplayName := user.UpdateDisplayNameEvent{
			DisplayName: newDisplayName,
		}
		bs, bsErr = json.Marshal(evUpdateDisplayName)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// update password - root cannot do this
		newPassword := safe.TrustedPassword(security.RandString())
		evUpdatePassword := user.UpdatePasswordEvent{
			Password: newPassword,
		}
		bs, bsErr = json.Marshal(evUpdatePassword)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)

		// update status
		evUpdateStatus := user.UpdateStatusEvent{
			Status: models.StatusInactive,
		}
		bs, bsErr = json.Marshal(evUpdateStatus)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// get response body (json serialized user)
		decoder := json.NewDecoder(resp.Body)
		decoder.DisallowUnknownFields()
		var usr user.User
		dcErr := decoder.Decode(&usr)
		require.NoError(t, dcErr)

		require.Equal(t, models.StatusInactive, usr.Meta.Status)
		require.Equal(t, newDisplayName, usr.DisplayName)
		require.NotEqual(t, previousAPISecret, usr.APISecret)
		uRead, uReadErr := user.Read(context.Background(), conn.Conn(), st.VersionKey, usr.ID)
		require.NoError(t, uReadErr)
		require.Equal(t, models.StatusInactive, uRead.Meta.Status)
		require.Equal(t, newDisplayName, uRead.DisplayName)
		require.NotEqual(t, previousAPISecret, uRead.APISecret)
	})

	t.Run("AsOrgOwner", func(t *testing_.T) {
		t.Parallel()
		// create new org, regularUser to test these updates
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()
		_, owner, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, oErr)

		// make token request for org owner
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

		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + regularUser.ID.String())
		require.NoError(t, urlErr)

		// update api secret
		previousAPISecret := regularUser.APISecret
		evUpdateAPISecret := user.UpdateAPISecretEvent{
			GenerateAPISecret: true,
		}
		bs, bsErr := json.Marshal(evUpdateAPISecret)
		require.NoError(t, bsErr)
		req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, putErr := c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// update display name
		newDisplayName := safe.TrustedVarChar(security.RandString())
		evUpdateDisplayName := user.UpdateDisplayNameEvent{
			DisplayName: newDisplayName,
		}
		bs, bsErr = json.Marshal(evUpdateDisplayName)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// update password - org owner cannot do this
		newPassword := safe.TrustedPassword(security.RandString())
		evUpdatePassword := user.UpdatePasswordEvent{
			Password: newPassword,
		}
		bs, bsErr = json.Marshal(evUpdatePassword)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)

		// update status
		evUpdateStatus := user.UpdateStatusEvent{
			Status: models.StatusInactive,
		}
		bs, bsErr = json.Marshal(evUpdateStatus)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// get response body (json serialized user)
		decoder := json.NewDecoder(resp.Body)
		decoder.DisallowUnknownFields()
		var usr user.User
		dcErr := decoder.Decode(&usr)
		require.NoError(t, dcErr)

		require.Equal(t, models.StatusInactive, usr.Meta.Status)
		require.Equal(t, newDisplayName, usr.DisplayName)
		require.NotEqual(t, previousAPISecret, usr.APISecret)
		uRead, uReadErr := user.Read(context.Background(), conn.Conn(), st.VersionKey, usr.ID)
		require.NoError(t, uReadErr)
		require.Equal(t, models.StatusInactive, uRead.Meta.Status)
		require.Equal(t, newDisplayName, uRead.DisplayName)
		require.NotEqual(t, previousAPISecret, uRead.APISecret)

		// try to put to a user (root) that org owner has no permission to access
		u, urlErr = url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + st.Root.ID.String())
		require.NoError(t, urlErr)
		evUpdateAPISecret = user.UpdateAPISecretEvent{
			GenerateAPISecret: true,
		}
		bs, bsErr = json.Marshal(evUpdateAPISecret)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("AsRegularUser", func(t *testing_.T) {
		t.Parallel()
		// create new regularUser to test these updates
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()
		_, _, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, oErr)
		tokenReqUrl, tokenReqUrlErr := url.Parse(srv.URL + "/token")
		require.NoError(t, tokenReqUrlErr)
		regularUserTokenRequest := jwt.EncodeTokenRequest(regularUser.ID, regularUser.APISecret.String())
		regularUserReq := http.Request{
			URL:    tokenReqUrl,
			Method: http.MethodPost,
			Header: map[string][]string{
				app.IDHeader:           {regularUser.ID.String()},
				app.TokenRequestHeader: {regularUserTokenRequest},
			},
		}
		resp, postErr := c.Do(&regularUserReq)
		require.NoError(t, postErr)
		require.Equal(t, resp.StatusCode, http.StatusOK)
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		require.NoError(t, readErr)
		var regularUserTok token.JSONToken
		umErr := json.Unmarshal(body, &regularUserTok)
		require.NoError(t, umErr)
		require.NotEmpty(t, regularUserTok.Token)

		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + regularUser.ID.String())
		require.NoError(t, urlErr)

		// update status - user cannot change their own status
		evUpdateStatus := user.UpdateStatusEvent{
			Status: models.StatusInactive,
		}
		bs, bsErr := json.Marshal(evUpdateStatus)
		require.NoError(t, bsErr)
		req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		resp, putErr := c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)

		// update api secret
		previousAPISecret := regularUser.APISecret
		evUpdateAPISecret := user.UpdateAPISecretEvent{
			GenerateAPISecret: true,
		}
		bs, bsErr = json.Marshal(evUpdateAPISecret)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// update display name
		newDisplayName := safe.TrustedVarChar(security.RandString())
		evUpdateDisplayName := user.UpdateDisplayNameEvent{
			DisplayName: newDisplayName,
		}
		bs, bsErr = json.Marshal(evUpdateDisplayName)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		// bad request because the token used has not been refreshed
		// since the API Secret was changed!
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// try to update display name again, but first get a new token
		// first, refresh regularUser to get the new API Secret
		var refreshErr error
		regularUser, refreshErr = user.Read(context.Background(), conn.Conn(), st.VersionKey, regularUser.ID)
		require.NoError(t, refreshErr)
		// get a new token
		regularUserTokenRequest = jwt.EncodeTokenRequest(regularUser.ID, regularUser.APISecret.String())
		regularUserReq = http.Request{
			URL:    tokenReqUrl,
			Method: http.MethodPost,
			Header: map[string][]string{
				app.IDHeader:           {regularUser.ID.String()},
				app.TokenRequestHeader: {regularUserTokenRequest},
			},
		}
		resp, postErr = c.Do(&regularUserReq)
		require.NoError(t, postErr)
		defer resp.Body.Close()
		body, readErr = io.ReadAll(resp.Body)
		require.NoError(t, readErr)
		umErr = json.Unmarshal(body, &regularUserTok)
		require.NoError(t, umErr)
		require.NotEmpty(t, regularUserTok.Token)
		// now try to update display name again
		bs, bsErr = json.Marshal(evUpdateDisplayName)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// update password
		newPassword := safe.TrustedPassword(security.RandString())
		evUpdatePassword := user.UpdatePasswordEvent{
			Password: newPassword,
		}
		bs, bsErr = json.Marshal(evUpdatePassword)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// get response body (json serialized user)
		decoder := json.NewDecoder(resp.Body)
		decoder.DisallowUnknownFields()
		var usr user.User
		dcErr := decoder.Decode(&usr)
		require.NoError(t, dcErr)

		require.Equal(t, models.StatusActive, usr.Meta.Status)
		require.Equal(t, newDisplayName, usr.DisplayName)
		require.NotEqual(t, previousAPISecret, usr.APISecret)
		uRead, uReadErr := user.Read(context.Background(), conn.Conn(), st.VersionKey, usr.ID)
		require.NoError(t, uReadErr)
		require.Equal(t, models.StatusActive, uRead.Meta.Status)
		require.Equal(t, newDisplayName, uRead.DisplayName)
		require.NotEqual(t, previousAPISecret, uRead.APISecret)
		// uRead has password populated, usr doesn't
		match, matchErr := security.VerifyPassword(newPassword.String(), uRead.Password)
		require.NoError(t, matchErr)
		require.True(t, match)

		// try to put to a user (root) that regular user has no permission to access
		u, urlErr = url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + st.Root.ID.String())
		require.NoError(t, urlErr)
		evUpdateAPISecret = user.UpdateAPISecretEvent{
			GenerateAPISecret: true,
		}
		bs, bsErr = json.Marshal(evUpdateAPISecret)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("NotFound", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + models.NewID().String())
		require.NoError(t, urlErr)
		evUpdateAPISecret := user.UpdateAPISecretEvent{
			GenerateAPISecret: true,
		}
		bs, bsErr := json.Marshal(evUpdateAPISecret)
		require.NoError(t, bsErr)
		req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, putErr := c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("MalformedUpdateEvent", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()
		_, _, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, oErr)
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + regularUser.ID.String())
		require.NoError(t, urlErr)

		// bad api secret update
		evUpdateAPISecret := user.UpdateAPISecretEvent{
			GenerateAPISecret: false,
		}
		bs, bsErr := json.Marshal(evUpdateAPISecret)
		require.NoError(t, bsErr)
		req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, putErr := c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)

		// bad display name update
		evUpdateDisplayName := user.UpdateDisplayNameEvent{
			DisplayName: safe.TrustedVarChar(""),
		}
		bs, bsErr = json.Marshal(evUpdateDisplayName)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)

		// bad status update
		evUpdateStatus := user.UpdateStatusEvent{
			Status: models.StatusNone,
		}
		bs, bsErr = json.Marshal(evUpdateStatus)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)

		// updating password can only be tested by regularUser
		tokenReqUrl, tokenReqUrlErr := url.Parse(srv.URL + "/token")
		require.NoError(t, tokenReqUrlErr)
		regularUserTokenRequest := jwt.EncodeTokenRequest(regularUser.ID, regularUser.APISecret.String())
		regularUserReq := http.Request{
			URL:    tokenReqUrl,
			Method: http.MethodPost,
			Header: map[string][]string{
				app.IDHeader:           {regularUser.ID.String()},
				app.TokenRequestHeader: {regularUserTokenRequest},
			},
		}
		resp, postErr := c.Do(&regularUserReq)
		require.NoError(t, postErr)
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		require.NoError(t, readErr)
		var regularUserTok token.JSONToken
		umErr := json.Unmarshal(body, &regularUserTok)
		require.NoError(t, umErr)
		require.NotEmpty(t, regularUserTok.Token)

		// bad password update
		evUpdatePassword := user.UpdatePasswordEvent{
			Password: safe.TrustedPassword(""),
		}
		bs, bsErr = json.Marshal(evUpdatePassword)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("NoMatchingEvent", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()
		// create user to PUT to
		_, _, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, oErr)

		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user/" + regularUser.ID.String())
		require.NoError(t, urlErr)

		// make up a type that does not match any event
		type Unknown struct {
			S string `json:"s"`
		}

		ev := Unknown{S: "hello"}
		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, putErr := c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}
