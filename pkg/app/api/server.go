package api

import (
	chi "github.com/go-chi/chi/v5"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
)

//const Version = "v0"

type Server struct {
	Rtr *chi.Router
	St  *app.State
}
