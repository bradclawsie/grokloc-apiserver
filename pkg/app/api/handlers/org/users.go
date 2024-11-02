package org

import (
	"context"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"

	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/render"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
)

func Users(st *app.State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := request.GetLogger(r)

		o, err := GetModel(r)
		if err != nil {
			logger.Error("get org model", "err", err)
		}

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

		userIDs, userIDsErr := org.Users(execCtx, conn.Conn(), o.ID)
		if userIDsErr != nil {
			if userIDsErr == models.ErrNotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
		}

		render.JSON(w, logger, userIDs)
	}
}
