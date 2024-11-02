package org

import (
	"context"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
)

func Delete(st *app.State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := request.GetLogger(r)

		o, err := GetModel(r)
		if err != nil {
			logger.Error("get org model", "err", err)
		}

		acquireCtx, acquireCancel := context.WithTimeout(context.Background(), st.ConnTimeout)
		defer acquireCancel()
		conn, connErr := st.Master.Acquire(acquireCtx)
		if connErr != nil {
			logger.Error("acquire master conn", "err", connErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer conn.Release()

		execUpdateCtx, execUpdateCtxCancel := context.WithTimeout(context.Background(), st.ExecTimeout)
		defer execUpdateCtxCancel()
		putErr := o.UpdateStatus(execUpdateCtx, conn.Conn(), models.StatusInactive)
		if putErr != nil {
			logger.Error("org delete", "err", putErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
