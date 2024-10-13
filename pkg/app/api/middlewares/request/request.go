package request

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
)

type IDType string

var IDKey = IDType("requestID")

type LoggerType string

var LoggerKey = LoggerType("logger")

// Middleware provides a per-request ID.
func Middleware(st *app.State) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			// set the unique requestID
			bs := make([]byte, 9)
			_, err := io.ReadFull(rand.Reader, bs)
			if err != nil {
				panic(err)
			}
			requestID := base64.StdEncoding.EncodeToString(bs)
			r = r.WithContext(context.WithValue(r.Context(), IDKey, requestID))

			// set the per-request logger
			if st.Logger == nil {
				panic("no state logger set")
			}
			logger := st.Logger.With(slog.Group("request",
				slog.String("id", requestID),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
			))
			r = r.WithContext(context.WithValue(r.Context(), LoggerKey, logger))

			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

// GetID returns the requestID. Panic indicates coding error.
func GetID(r *http.Request) string {
	v := r.Context().Value(IDKey)
	if v == nil {
		panic("retrieve requestID from context")
	}
	requestID, a := v.(string)
	if !a {
		panic("assert requestID -> string")
	}
	return requestID
}

// GetLogger returns the logger. Panic indicates coding error.
func GetLogger(r *http.Request) *slog.Logger {
	v := r.Context().Value(LoggerKey)
	if v == nil {
		panic("retrieve logger from context")
	}
	logger, a := v.(*slog.Logger)
	if !a {
		panic("assert logger -> *slog.Logger")
	}
	return logger
}
