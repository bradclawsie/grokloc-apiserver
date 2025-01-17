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

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/token"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
)

var (
	c                             http.Client
	o                             *org.Org
	owner, regularUser            *user.User
	srv                           *httptest.Server
	st                            *app.State
	tok, ownerTok, regularUserTok token.JSONToken
)

func TestMain(m *testing_.M) {
	var stErr error
	st, stErr = unit.State()
	if stErr != nil {
		log.Fatal(stErr.Error())
	}
	rtr := api.NewRouter(st)
	srv = httptest.NewServer(rtr)
	c = http.Client{}

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
		log.Fatal("resp.StatusCode != http.StatusOK")
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
		log.Fatal("resp.StatusCode != http.StatusOK")
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
		log.Fatal("owner token empty")
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
		log.Fatal("resp.StatusCode != http.StatusOK")
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
		log.Fatal("regular user token empty")
	}
}
