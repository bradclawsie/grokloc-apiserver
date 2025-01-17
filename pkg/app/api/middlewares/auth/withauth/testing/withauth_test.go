package testing

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	testing_ "testing"

	"github.com/go-chi/chi/v5"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/token"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withauth"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
)

var (
	c                                          http.Client
	o                                          *org.Org
	owner, regularUser, peerUser               *user.User
	srv                                        *httptest.Server
	st                                         *app.State
	tok, ownerTok, regularUserTok, peerUserTok token.JSONToken
)

func TestMain(m *testing_.M) {
	var stErr error
	st, stErr = unit.State()
	if stErr != nil {
		log.Fatal(stErr.Error())
	}

	c = http.Client{}

	rtr := chi.NewRouter()
	rtr.Use(request.Middleware(st))
	rtr.Use(withuser.Middleware(st))
	rtr.Route("/token", func(rtr chi.Router) {
		rtr.Post("/", token.Post(st))
	})
	rtr.Route("/root", func(rtr chi.Router) {
		rtr.Use(withauth.RequireOneOf(st, withuser.AuthRoot))
		rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {})
	})
	rtr.Route("/org", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(withmodel.Middleware(st, models.KindOrg))
			rtr.Use(withauth.RequireOneOf(st, withuser.AuthRoot, withuser.AuthOrg))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {})
		})
	})
	rtr.Route("/user", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(withmodel.Middleware(st, models.KindUser))
			rtr.Use(withauth.RequireOneOf(st, withuser.AuthRoot, withuser.AuthOrg, withuser.AuthUser))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {})
		})
	})
	rtr.Route("/peer", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(withmodel.Middleware(st, models.KindUser))
			rtr.Use(withauth.RequireOneOf(st, withuser.AuthRoot, withuser.AuthOrg, withuser.AuthUser, withuser.AuthPeer))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {})
		})
	})

	srv = httptest.NewServer(rtr)

	conn, connErr := st.Master.Acquire(context.Background())
	if connErr != nil {
		log.Fatal(connErr.Error())
	}
	defer conn.Release()
	var createErr error
	o, owner, regularUser, createErr = app_testing.TestOrgAndUser(conn.Conn(), st)
	if createErr != nil {
		log.Fatal(createErr.Error())
	}

	displayName := safe.TrustedVarChar(security.RandString())
	email := safe.TrustedVarChar(security.RandString())
	password, passwordErr := security.DerivePassword(security.RandString(), st.Argon2Config)
	if passwordErr != nil {
		log.Fatal(passwordErr.Error())
	}
	peerUser, createErr = user.Create(context.Background(), conn.Conn(), displayName, email, o.ID, *password, st.VersionKey)
	if createErr != nil {
		log.Fatal(createErr.Error())
	}
	updateErr := peerUser.UpdateStatus(context.Background(), conn.Conn(), st.VersionKey, models.StatusActive)
	if updateErr != nil {
		log.Fatal(updateErr.Error())
	}

	u, urlErr := url.Parse(srv.URL + "/token")
	if urlErr != nil {
		log.Fatal(urlErr.Error())
	}
	tokenRequest := jwt.EncodeTokenRequest(st.Root.ID, st.Root.APISecret.String())
	req := http.Request{
		URL:    u,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {st.Root.ID.String()},
			app.TokenRequestHeader: {tokenRequest},
		},
	}
	resp, postErr := c.Do(&req)
	if postErr != nil {
		log.Fatal(postErr.Error())
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatal("status not ok")
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		log.Fatal(readErr.Error())
	}
	umErr := json.Unmarshal(body, &tok)
	if umErr != nil {
		log.Fatal(umErr.Error())
	}
	if len(tok.Token) == 0 {
		log.Fatal("token empty")
	}

	tokenRequest = jwt.EncodeTokenRequest(owner.ID, owner.APISecret.String())
	req = http.Request{
		URL:    u,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {owner.ID.String()},
			app.TokenRequestHeader: {tokenRequest},
		},
	}
	resp, postErr = c.Do(&req)
	if postErr != nil {
		log.Fatal(postErr.Error())
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatal("status not ok")
	}
	defer resp.Body.Close()
	body, readErr = io.ReadAll(resp.Body)
	if readErr != nil {
		log.Fatal(readErr.Error())
	}
	umErr = json.Unmarshal(body, &ownerTok)
	if umErr != nil {
		log.Fatal(umErr.Error())
	}
	if len(ownerTok.Token) == 0 {
		log.Fatal("token empty")
	}

	tokenRequest = jwt.EncodeTokenRequest(regularUser.ID, regularUser.APISecret.String())
	req = http.Request{
		URL:    u,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {regularUser.ID.String()},
			app.TokenRequestHeader: {tokenRequest},
		},
	}
	resp, postErr = c.Do(&req)
	if postErr != nil {
		log.Fatal(postErr.Error())
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatal("status not ok")
	}
	defer resp.Body.Close()
	body, readErr = io.ReadAll(resp.Body)
	if readErr != nil {
		log.Fatal(readErr.Error())
	}
	umErr = json.Unmarshal(body, &regularUserTok)
	if umErr != nil {
		log.Fatal(umErr.Error())
	}
	if len(regularUserTok.Token) == 0 {
		log.Fatal("token empty")
	}

	tokenRequest = jwt.EncodeTokenRequest(peerUser.ID, peerUser.APISecret.String())
	req = http.Request{
		URL:    u,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {peerUser.ID.String()},
			app.TokenRequestHeader: {tokenRequest},
		},
	}
	resp, postErr = c.Do(&req)
	if postErr != nil {
		log.Fatal(postErr.Error())
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatal("status not ok")
	}
	defer resp.Body.Close()
	body, readErr = io.ReadAll(resp.Body)
	if readErr != nil {
		log.Fatal(readErr.Error())
	}
	umErr = json.Unmarshal(body, &peerUserTok)
	if umErr != nil {
		log.Fatal(umErr.Error())
	}
	if len(peerUserTok.Token) == 0 {
		log.Fatal("token empty")
	}

	m.Run()
}

func TestWithAuth(t *testing_.T) {
	t.Run("TestRootAuthAsRoot", func(t *testing_.T) {
		u, urlErr := url.Parse(srv.URL + "/root")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("TestRootAuthAsOrgOwner", func(t *testing_.T) {
		u, urlErr := url.Parse(srv.URL + "/root")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("TestRootAuthAsRegularUser", func(t *testing_.T) {
		u, urlErr := url.Parse(srv.URL + "/root")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("TestOrgAuthAsRoot", func(t *testing_.T) {
		u, urlErr := url.Parse(srv.URL + "/org/" + o.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("TestOrgAuthAsOrgOwner", func(t *testing_.T) {
		u, urlErr := url.Parse(srv.URL + "/org/" + o.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("TestOrgAuthAsOrgOwnerAccessOtherOrg", func(t *testing_.T) {
		u, urlErr := url.Parse(srv.URL + "/org/" + st.Org.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("TestOrgAuthAsRegularUser", func(t *testing_.T) {
		u, urlErr := url.Parse(srv.URL + "/org/" + o.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("TestUserAuthAsRoot", func(t *testing_.T) {
		u, urlErr := url.Parse(srv.URL + "/user/" + regularUser.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(tok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("TestUserAuthAsOrgOwner", func(t *testing_.T) {
		u, urlErr := url.Parse(srv.URL + "/user/" + regularUser.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("TestUserAuthAsOrgOwnerAccessOtherOrgUser", func(t *testing_.T) {
		u, urlErr := url.Parse(srv.URL + "/user/" + st.Root.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("TestUserAuthAsRegularUser", func(t *testing_.T) {
		u, urlErr := url.Parse(srv.URL + "/user/" + regularUser.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("TestUserAuthAsRegularUserPeerUser", func(t *testing_.T) {
		u, urlErr := url.Parse(srv.URL + "/user/" + peerUser.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("TestUserAuthAsRegularUserOtherOrgUser", func(t *testing_.T) {
		u, urlErr := url.Parse(srv.URL + "/user/" + st.Root.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("TestUserAuthAsPeerUser", func(t *testing_.T) {
		u, urlErr := url.Parse(srv.URL + "/peer/" + regularUser.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, peerUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(peerUserTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("TestUserAuthAsPeerUserOtherOrgUser", func(t *testing_.T) {
		u, urlErr := url.Parse(srv.URL + "/peer/" + st.Root.ID.String())
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, peerUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(peerUserTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}
