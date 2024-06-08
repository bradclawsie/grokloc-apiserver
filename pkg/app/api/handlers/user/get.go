package user

import (
	"context"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/render"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
)

func Get(st *app.State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := request.GetLogger(r)

		// read in user; needed to establish auth scope
		acquireCtx, acquireCancel := context.WithTimeout(context.Background(), st.ConnTimeout)
		defer acquireCancel()
		conn, connErr := st.RandomReplica().Acquire(acquireCtx)
		if connErr != nil {
			logger.Error("acquire replica conn", "err", connErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer conn.Release()

		execCtx, execCtxCancel := context.WithTimeout(context.Background(), st.ExecTimeout)
		defer execCtxCancel()
		u, uErr := user.Read(execCtx, conn.Conn(), st.VersionKey, withmodel.GetID(r))
		if uErr != nil {
			if uErr == models.ErrNotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			logger.Error("user read", "err", uErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		scopedAuth := withuser.GetUserScopedAuth(r, u)
		if scopedAuth == withuser.AuthNone {
			logger.Debug("not root or org owner or own user",
				"err", app.ErrorInadequateAuthorization)
			http.Error(w, app.ErrorInadequateAuthorization.Error(), http.StatusForbidden)
			return
		}

		render.JSON(w, logger, u)
	}
}
