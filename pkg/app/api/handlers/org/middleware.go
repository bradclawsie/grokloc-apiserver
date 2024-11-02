package org

import (
	"errors"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
)

// LoadModel loads the Org identified with the url parameter `id`.
// See withmodel for tests.
func LoadModel(st *app.State) func(http.Handler) http.Handler {
	return withmodel.Middleware(st, models.KindOrg)
}

// GetModel retrieves the Org model loaded by LoadModel.
// See withmodel for tests.
func GetModel(r *http.Request) (*org.Org, error) {
	modelObject := withmodel.GetModelAny(r)
	o, ok := modelObject.(*org.Org)
	if !ok {
		return nil, errors.New("middleware cached object not coerced to *org.Org")
	}
	return o, nil
}
