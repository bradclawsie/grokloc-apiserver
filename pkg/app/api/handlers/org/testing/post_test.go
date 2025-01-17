package testing

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	testing_ "testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
)

func TestPost(t *testing_.T) {
	t.Run("AsRoot", func(t *testing_.T) {
		t.Parallel()

		ev := org.CreateEvent{
			Name:             safe.TrustedVarChar(security.RandString()),
			OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
			OwnerEmail:       safe.TrustedVarChar(security.RandString()),
			OwnerPassword:    safe.TrustedPassword(security.RandString()),
			Role:             st.DefaultRole,
		}
		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, postErr := c.Do(req)
		require.NoError(t, postErr)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		// get response body (json serialized org)
		decoder := json.NewDecoder(resp.Body)
		decoder.DisallowUnknownFields()
		var o org.Org
		dcErr := decoder.Decode(&o)
		require.NoError(t, dcErr)
		require.Equal(t, ev.Name, o.Name)
		// parse the id from the location, then do a read on it
		// to verify
		location, locationErr := resp.Location()
		require.NoError(t, locationErr)
		pathElts := strings.Split(location.Path, "/")
		require.True(t, len(pathElts) != 0)
		id := pathElts[len(pathElts)-1]
		require.Equal(t, o.ID.String(), id)
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()
		oRead, oReadErr := org.Read(context.Background(), conn.Conn(), o.ID)
		require.NoError(t, oReadErr)
		require.Equal(t, o.ID.String(), oRead.ID.String())
		uRead, uReadErr := user.Read(context.Background(), conn.Conn(), st.VersionKey, oRead.Owner)
		require.NoError(t, uReadErr)
		require.Equal(t, ev.OwnerDisplayName, uRead.DisplayName)
		require.Equal(t, ev.OwnerEmail, uRead.Email)
		require.NotEqual(t, ev.OwnerPassword, uRead.Password)
		match, matchErr := security.VerifyPassword(ev.OwnerPassword.String(), uRead.Password)
		require.NoError(t, matchErr)
		require.True(t, match)
	})

	t.Run("AsOrgOwner", func(t *testing_.T) {
		t.Parallel()
		ev := org.CreateEvent{
			Name:             safe.TrustedVarChar(security.RandString()),
			OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
			OwnerEmail:       safe.TrustedVarChar(security.RandString()),
			OwnerPassword:    safe.TrustedPassword(security.RandString()),
			Role:             st.DefaultRole,
		}
		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, postErr := c.Do(req)
		require.NoError(t, postErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("AsRegularUser", func(t *testing_.T) {
		t.Parallel()
		ev := org.CreateEvent{
			Name:             safe.TrustedVarChar(security.RandString()),
			OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
			OwnerEmail:       safe.TrustedVarChar(security.RandString()),
			OwnerPassword:    safe.TrustedPassword(security.RandString()),
			Role:             st.DefaultRole,
		}
		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org")
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
		evs := []org.CreateEvent{
			{
				Name:             safe.TrustedVarChar(""),
				OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
				OwnerEmail:       safe.TrustedVarChar(security.RandString()),
				OwnerPassword:    safe.TrustedPassword(security.RandString()),
				Role:             st.DefaultRole,
			},
			{
				Name:             safe.TrustedVarChar(security.RandString()),
				OwnerDisplayName: safe.TrustedVarChar("    "),
				OwnerEmail:       safe.TrustedVarChar(security.RandString()),
				OwnerPassword:    safe.TrustedPassword(security.RandString()),
				Role:             st.DefaultRole,
			},
			{
				Name:             safe.TrustedVarChar(security.RandString()),
				OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
				OwnerEmail:       safe.TrustedVarChar(""),
				OwnerPassword:    safe.TrustedPassword(security.RandString()),
				Role:             st.DefaultRole,
			},
			{
				Name:             safe.TrustedVarChar(security.RandString()),
				OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
				OwnerEmail:       safe.TrustedVarChar(security.RandString()),
				OwnerPassword:    safe.TrustedPassword(" "),
				Role:             st.DefaultRole,
			},
		}

		for _, ev := range evs {
			bs, bsErr := json.Marshal(ev)
			require.NoError(t, bsErr)
			u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org")
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
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org")
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
		ev := org.CreateEvent{
			Name:             safe.TrustedVarChar(security.RandString()),
			OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
			OwnerEmail:       safe.TrustedVarChar(security.RandString()),
			OwnerPassword:    safe.TrustedPassword(security.RandString()),
			Role:             st.DefaultRole,
		}
		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, postErr := c.Do(req)
		require.NoError(t, postErr)
		require.Equal(t, http.StatusCreated, resp.StatusCode)

		// resend with org name already in use
		req, reqErr = http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, postErr = c.Do(req)
		require.NoError(t, postErr)
		require.Equal(t, http.StatusConflict, resp.StatusCode)
	})
}
