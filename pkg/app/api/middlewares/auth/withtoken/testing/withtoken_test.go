package testing

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	go_jwt "github.com/golang-jwt/jwt/v5"

	testing_ "testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/token"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/stretchr/testify/require"
)

var (
	c                  http.Client
	o                  *org.Org
	owner, regularUser *user.User
	srv                *httptest.Server
	st                 *app.State
)

func TestMain(m *testing_.M) {
	var stErr error
	st, stErr = unit.State()
	if stErr != nil {
		log.Fatal(stErr.Error())
	}

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

	rtr := api.NewRouter(st)
	srv = httptest.NewServer(rtr)
	c = http.Client{}
}

func TestWithToken(t *testing_.T) {
	t.Run("TestValidAuth", func(t *testing_.T) {
		t.Parallel()
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
		require.Equal(t, http.StatusOK, resp.StatusCode)
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		require.NoError(t, readErr)
		var regularUserTok token.JSONToken
		umErr := json.Unmarshal(body, &regularUserTok)
		require.NoError(t, umErr)
		require.NotEmpty(t, regularUserTok.Token)

		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/ok")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("TestMissingToken", func(t *testing_.T) {
		t.Parallel()
		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/ok")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		// token is missing
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("TestWrongID", func(t *testing_.T) {
		t.Parallel()
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
		require.Equal(t, http.StatusOK, resp.StatusCode)
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		require.NoError(t, readErr)
		var regularUserTok token.JSONToken
		umErr := json.Unmarshal(body, &regularUserTok)
		require.NoError(t, umErr)
		require.NotEmpty(t, regularUserTok.Token)

		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/ok")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, owner.ID.String()) // should be regularUser
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("TestWrongAPISecret", func(t *testing_.T) {
		t.Parallel()
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
		require.Equal(t, http.StatusOK, resp.StatusCode)
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		require.NoError(t, readErr)
		var regularUserTok token.JSONToken
		umErr := json.Unmarshal(body, &regularUserTok)
		require.NoError(t, umErr)
		require.NotEmpty(t, regularUserTok.Token)

		// change regularUser's api secret, invalidating the token
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()
		// generate new, random api secret
		updateErr := regularUser.UpdateAPISecret(context.Background(), conn.Conn(), st.VersionKey)
		require.NoError(t, updateErr)

		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/ok")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("TestBadToken", func(t *testing_.T) {
		t.Parallel()
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
		require.Equal(t, http.StatusOK, resp.StatusCode)
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		require.NoError(t, readErr)
		var regularUserTok token.JSONToken
		umErr := json.Unmarshal(body, &regularUserTok)
		require.NoError(t, umErr)
		require.NotEmpty(t, regularUserTok.Token)

		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/ok")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, "not.a.token") // in place of token
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("TestExpiredToken", func(t *testing_.T) {
		t.Parallel()
		now := time.Now().Unix()
		tokenRequest := jwt.EncodeTokenRequest(regularUser.ID, regularUser.APISecret.String())
		tok := go_jwt.NewWithClaims(go_jwt.SigningMethodHS256, go_jwt.MapClaims{
			"iss": "GrokLOC.com",
			"sub": tokenRequest,
			"nbf": now,
			"iat": now,
			"exp": now - jwt.Expiration,
		})
		regularUserToken, tokenErr := tok.SignedString(st.SigningKey)
		require.NoError(t, tokenErr)

		u, urlErr := url.Parse(srv.URL + app.APIPath + st.APIVersion + "/ok")
		require.NoError(t, urlErr)
		req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
		require.NoError(t, reqErr)
		req.Header.Add(app.IDHeader, regularUser.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserToken))
		resp, getErr := c.Do(req)
		require.NoError(t, getErr)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}
