// Package org contains package methods for org support.
package org

import (
	"github.com/grokloc/grokloc-go/pkg/app/models"
	"github.com/grokloc/grokloc-go/pkg/safe"
)

// Org models a row of the orgs table.
type Org struct {
	models.Base
	Name  safe.VarChar `json:"name"`
	Owner models.ID    `json:"owner"`
}

const SchemaVersion = 0
