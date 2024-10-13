// Package repository contains package methods for git repository support.
package repository

import (
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
)

// Repository models a row of the orgs table.
type Repository struct {
	models.Base
	Name  safe.VarChar `json:"name"`
	Org   models.ID    `json:"org"`
	Owner models.ID    `json:"owner"`
	Path  string       `json:"path"`
}

// GetID implements models.WithID.
func (r *Repository) GetID() models.ID {
	return r.ID
}

// GetRepository implements models.WithRepository.
func (r *Repository) GetRepository() models.ID {
	return r.GetID()
}

// GetRepository implements models.WithOrg.
func (r *Repository) GetOrg() models.ID {
	return r.Org
}

// GetRepository implements models.WithUser.
func (r *Repository) GetUser() models.ID {
	return r.Owner
}

const SchemaVersion = 0
