package withtoken

import (
	"fmt"
	"net/http"
	"time"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
)

// Middleware tests the Authorization header.
// Assumes request and withuser middlewares.
func Middleware(st *app.State) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			logger := request.GetLogger(r)

			// retrieve signed token header
			signedToken, headerErr := jwt.HeaderValueToSignedString(r.Header.Get(app.AuthorizationHeader))
			if headerErr != nil {
				logger.Debug("malformed request", "missing or malformed header", app.AuthorizationHeader)
				http.Error(w, fmt.Sprintf("missing/malformed header %s", app.AuthorizationHeader), http.StatusBadRequest)
				return
			}

			// decode token
			token, tokenErr := jwt.Decode(signedToken, st.SigningKey)
			if tokenErr != nil {
				logger.Error("token decode", "err", tokenErr)
				http.Error(w, "malformed token", http.StatusBadRequest)
				return
			}

			// test expiration
			exp, expErr := token.Claims.GetExpirationTime()
			if expErr != nil {
				logger.Debug("token validate", "invalid expiration", expErr)
				http.Error(w, "malformed token", http.StatusBadRequest)
				return
			}
			if time.Now().After(exp.Time) {
				logger.Debug("token expired")
				http.Error(w, "token expired", http.StatusBadRequest)
				return
			}

			// test user id match
			subject, subjectErr := token.Claims.GetSubject()
			if subjectErr != nil {
				logger.Debug("token claims sub missing")
				http.Error(w, "malformed token", http.StatusBadRequest)
				return
			}
			u := withuser.GetUser(r) // assume withuser middleware
			// if u.APISecret has been changed since the token was issued,
			// this will fail (caller must get a new token)
			if jwt.EncodeTokenRequest(u.ID, u.APISecret.String()) != subject {
				logger.Debug("claims subject does not match token request", "sub", subject)
				http.Error(w, "malformed token", http.StatusBadRequest)
				return
			}

			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}
