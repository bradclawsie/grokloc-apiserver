package user

import (
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/render"
)

func Get(st *app.State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := request.GetLogger(r)

		u, err := GetModel(r)
		if err != nil {
			logger.Error("get user model", "err", err)
		}

		render.JSON(w, logger, u)
	}
}
