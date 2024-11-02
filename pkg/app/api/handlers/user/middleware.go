package user

import (
	"errors"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
)

// LoadModel loads the User identified with the url parameter `id`.
// See withmodel for tests.
func LoadModel(st *app.State) func(http.Handler) http.Handler {
	return withmodel.Middleware(st, models.KindUser)
}

// GetModel retrieves the User model loaded by LoadModel.
// See withmodel for tests.
func GetModel(r *http.Request) (*user.User, error) {
	modelObject := withmodel.GetModelAny(r)
	u, ok := modelObject.(*user.User)
	if !ok {
		return nil, errors.New("middleware cached object not coerced to *user.User")
	}
	return u, nil
}
