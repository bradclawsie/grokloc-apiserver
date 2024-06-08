package user

import (
	"context"
	"net/http"

	"github.com/grokloc/grokloc-go/pkg/app"
	"github.com/grokloc/grokloc-go/pkg/app/admin/user"
	"github.com/grokloc/grokloc-go/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-go/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-go/pkg/app/api/middlewares/withmodel"
	"github.com/grokloc/grokloc-go/pkg/app/models"
)

// Delete updates a user to have status inactive.
func Delete(st *app.State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := request.GetLogger(r)

		acquireCtx, acquireCancel := context.WithTimeout(context.Background(), st.ConnTimeout)
		defer acquireCancel()
		conn, connErr := st.Master.Acquire(acquireCtx)
		if connErr != nil {
			logger.Error("acquire master conn", "err", connErr)
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
		// only root or the org owner can delete a user
		if scopedAuth != withuser.AuthRoot && scopedAuth != withuser.AuthOrg {
			logger.Debug("not root or org owner",
				"err", app.ErrorInadequateAuthorization)
			http.Error(w, app.ErrorInadequateAuthorization.Error(), http.StatusForbidden)
			return
		}

		execUpdateCtx, execUpdateCtxCancel := context.WithTimeout(context.Background(), st.ExecTimeout)
		defer execUpdateCtxCancel()
		putErr := u.UpdateStatus(execUpdateCtx, conn.Conn(), st.VersionKey, models.StatusInactive)
		if putErr != nil {
			logger.Error("user delete", "err", putErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
