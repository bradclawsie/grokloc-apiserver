package body

import (
	"context"
	"io"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
)

type BodyType string

var BodyKey = BodyType("body")

// Middleware reads in an expected body payload.
func Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			logger := request.GetLogger(r)

			body, bodyErr := io.ReadAll(http.MaxBytesReader(w, r.Body, app.MaxBodySize))
			defer r.Body.Close()
			if bodyErr != nil || len(body) == 0 {
				logger.Debug("body read", "err", app.ErrorBody)
				http.Error(w, app.ErrorBody.Error(), http.StatusBadRequest)
				return
			}

			r = r.WithContext(context.WithValue(r.Context(), BodyKey, body))
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

// FromRequest returns the request body. Panic indicates coding error.
func FromRequest(r *http.Request) []byte {
	v := r.Context().Value(BodyKey)
	if v == nil {
		panic("retrieve body from context")
	}
	body, a := v.([]byte)
	if !a {
		panic("assert body -> []byte")
	}
	return body
}
