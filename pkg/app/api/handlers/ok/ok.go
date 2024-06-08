// Package ok provides an unauthenticated healthcheck handler.
package ok

import (
	"net/http"

	"github.com/grokloc/grokloc-go/pkg/app/api/middlewares/request"
)

// Get provides an unauthenticated ping service.
// Assumes request middleware.
func Get() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, wErr := w.Write([]byte("OK:" + request.GetID(r)))
		if wErr != nil {
			request.GetLogger(r).Error("response write", "err", wErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
}
