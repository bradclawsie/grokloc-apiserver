package testing

import (
	"bytes"
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

func TestPut(t *testing_.T) {
	t.Run("AsRoot", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()
		// create an org to PUT to
		o, _, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), st)
		require.NoError(t, oErr)

		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org/" + o.ID.String())
		require.NoError(t, urlErr)

		// set to inactive
		evStatus := org.UpdateStatusEvent{
			Status: models.StatusInactive,
		}
		bs, bsErr := json.Marshal(evStatus)
		require.NoError(t, bsErr)
		req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, putErr := c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		// get response body (json serialized org)
		decoder := json.NewDecoder(resp.Body)
		decoder.DisallowUnknownFields()
		var oRead0 org.Org
		dcErr := decoder.Decode(&oRead0)
		require.NoError(t, dcErr)
		require.Equal(t, models.StatusInactive, oRead0.Meta.Status)

		// set owner to be regularUser
		evOwner := org.UpdateOwnerEvent{
			Owner: regularUser.ID,
		}
		bs, bsErr = json.Marshal(evOwner)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		// get response body (json serialized org)
		decoder = json.NewDecoder(resp.Body)
		decoder.DisallowUnknownFields()
		var oRead1 org.Org
		dcErr = decoder.Decode(&oRead1)
		require.NoError(t, dcErr)
		require.Equal(t, regularUser.ID, oRead1.Owner)

		// try nonexistant user as candidate owner
		require.NoError(t, urlErr)
		evOwner = org.UpdateOwnerEvent{
			Owner: models.NewID(),
		}
		bs, bsErr = json.Marshal(evOwner)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)

		// try nonexistant org
		u, urlErr = url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org/" + models.NewID().String())
		require.NoError(t, urlErr)
		evOwner = org.UpdateOwnerEvent{
			Owner: regularUser.ID,
		}
		bs, bsErr = json.Marshal(evOwner)
		require.NoError(t, bsErr)
		req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, putErr = c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("AsOrgOwner", func(t *testing_.T) {
		t.Parallel()
		// try to set to inactive
		ev := org.UpdateStatusEvent{
			Status: models.StatusInactive,
		}
		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org/" + o.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, putErr := c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("AsRegularUser", func(t *testing_.T) {
		t.Parallel()
		// try to set to inactive
		ev := org.UpdateStatusEvent{
			Status: models.StatusInactive,
		}
		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org/" + o.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		resp, putErr := c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("NotFound", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/org/" + models.NewID().String())
		require.NoError(t, urlErr)

		// set to inactive
		evStatus := org.UpdateStatusEvent{
			Status: models.StatusInactive,
		}
		bs, bsErr := json.Marshal(evStatus)
		require.NoError(t, bsErr)
		req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, putErr := c.Do(req)
		require.NoError(t, putErr)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}
