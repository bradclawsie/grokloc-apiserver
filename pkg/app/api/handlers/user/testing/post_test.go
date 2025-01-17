package testing

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	testing_ "testing"

	"github.com/google/uuid"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
)

func TestPost(t *testing_.T) {
	t.Run("AsRoot", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()
		ev := user.CreateEvent{
			DisplayName: safe.TrustedVarChar(security.RandString()),
			Email:       safe.TrustedVarChar(security.RandString()),
			Org:         o.ID,
			Password:    safe.TrustedPassword(security.RandString()),
		}
		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, postErr := c.Do(req)
		require.NoError(t, postErr)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		decoder := json.NewDecoder(resp.Body)
		decoder.DisallowUnknownFields()
		var usr user.User
		dcErr := decoder.Decode(&usr)
		require.NoError(t, dcErr)
		// parse the id from the location, then do a read on it
		// to verify
		location, locationErr := resp.Location()
		require.NoError(t, locationErr)
		pathElts := strings.Split(location.Path, "/")
		require.True(t, len(pathElts) != 0)
		id := pathElts[len(pathElts)-1]
		require.Equal(t, usr.ID.String(), id)
		uRead, uReadErr := user.Read(context.Background(), conn.Conn(), st.VersionKey, usr.ID)
		require.NoError(t, uReadErr)
		require.Equal(t, usr.ID.String(), uRead.ID.String())
		require.Equal(t, ev.DisplayName, uRead.DisplayName)
		require.Equal(t, ev.Email, uRead.Email)
		// password will be derived when uploaded
		require.NotEqual(t, ev.Password, uRead.Password)
		require.Equal(t, ev.Org, uRead.Org)
		match, matchErr := security.VerifyPassword(ev.Password.String(), uRead.Password)
		require.NoError(t, matchErr)
		require.True(t, match)
	})

	t.Run("AsOrgOwner", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		// try to create a user in owner's org
		ev := user.CreateEvent{
			DisplayName: safe.TrustedVarChar(security.RandString()),
			Email:       safe.TrustedVarChar(security.RandString()),
			Org:         o.ID,
			Password:    safe.TrustedPassword(security.RandString()),
		}
		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, postErr := c.Do(req)
		require.NoError(t, postErr)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		// get response body (json serialized user)
		decoder := json.NewDecoder(resp.Body)
		decoder.DisallowUnknownFields()
		var usr user.User
		dcErr := decoder.Decode(&usr)
		require.NoError(t, dcErr)
		// parse the id from the location, then do a read on it
		// to verify
		location, locationErr := resp.Location()
		require.NoError(t, locationErr)
		pathElts := strings.Split(location.Path, "/")
		require.True(t, len(pathElts) != 0)
		id := pathElts[len(pathElts)-1]
		require.Equal(t, usr.ID.String(), id)
		uRead, uReadErr := user.Read(context.Background(), conn.Conn(), st.VersionKey, usr.ID)
		require.NoError(t, uReadErr)
		require.Equal(t, usr.ID.String(), uRead.ID.String())
		require.Equal(t, ev.DisplayName, uRead.DisplayName)
		require.Equal(t, ev.Email, uRead.Email)
		require.NotEqual(t, ev.Password, uRead.Password)
		require.Equal(t, ev.Org, uRead.Org)

		// try to have the org owner set a user in an org not theirs
		ev.Org = st.Org.ID // root org
		bs, bsErr = json.Marshal(ev)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, postErr = c.Do(req)
		require.NoError(t, postErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("AsRegularUser", func(t *testing_.T) {
		t.Parallel()
		ev := user.CreateEvent{
			DisplayName: safe.TrustedVarChar(security.RandString()),
			Email:       safe.TrustedVarChar(security.RandString()),
			Org:         o.ID,
			Password:    safe.TrustedPassword(security.RandString()),
		}
		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		resp, postErr := c.Do(req)
		require.NoError(t, postErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("MalformedCreateEvent", func(t *testing_.T) {
		t.Parallel()
		var empty uuid.UUID
		evs := []user.CreateEvent{
			{
				DisplayName: safe.TrustedVarChar(""),
				Email:       safe.TrustedVarChar(security.RandString()),
				Org:         models.NewID(),
				Password:    safe.TrustedPassword(security.RandString()),
			},
			{
				DisplayName: safe.TrustedVarChar(security.RandString()),
				Email:       safe.TrustedVarChar("  "),
				Org:         models.NewID(),
				Password:    safe.TrustedPassword(security.RandString()),
			},
			{
				DisplayName: safe.TrustedVarChar(security.RandString()),
				Email:       safe.TrustedVarChar(security.RandString()),
				Org:         models.ID(empty),
				Password:    safe.TrustedPassword(security.RandString()),
			},
			{
				DisplayName: safe.TrustedVarChar(security.RandString()),
				Email:       safe.TrustedVarChar(security.RandString()),
				Org:         models.NewID(),
				Password:    safe.TrustedPassword(" "),
			},
		}

		for _, ev := range evs {
			bs, bsErr := json.Marshal(ev)
			require.NoError(t, bsErr)
			u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user")
			require.NoError(t, urlErr)
			req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
			require.NoError(t, reqErr)
			req.Header.Add(app.IDHeader, st.Root.ID.String())
			req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
			resp, postErr := c.Do(req)
			require.NoError(t, postErr)
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		}
	})

	t.Run("NoMatchingEvent", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user")
		require.NoError(t, urlErr)

		// make up a type that does not match any event
		type Unknown struct {
			S string `json:"s"`
		}
		ev := Unknown{S: "hello"}
		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, postErr := c.Do(req)
		require.NoError(t, postErr)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Conflict", func(t *testing_.T) {
		t.Parallel()
		ev := user.CreateEvent{
			DisplayName: safe.TrustedVarChar(security.RandString()),
			Email:       safe.TrustedVarChar(security.RandString()),
			Org:         o.ID,
			Password:    safe.TrustedPassword(security.RandString()),
		}
		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/user")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, postErr := c.Do(req)
		require.NoError(t, postErr)
		require.Equal(t, http.StatusCreated, resp.StatusCode)

		// resend with user email already in use in org
		req, reqErr = http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, postErr = c.Do(req)
		require.NoError(t, postErr)
		require.Equal(t, http.StatusConflict, resp.StatusCode)
	})
}
