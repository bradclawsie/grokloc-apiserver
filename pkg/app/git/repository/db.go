package repository

import (
	"context"

	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/jackc/pgx/v5"
)

func (r *Repository) Insert(ctx context.Context, conn *pgx.Conn) error {
	const insertQuery = `
			insert into repositories 
			(id, name, org, owner, path, schema_version, status) 
			values 
			($1, $2, $3, $4, $5, $6, $7)
		`

	result, err := conn.Exec(ctx, insertQuery,
		r.ID,
		r.Name,
		r.Org,
		r.Owner,
		r.Meta.Role,
		r.Meta.SchemaVersion,
		r.Meta.Status,
	)
	if err != nil {
		if models.UniqueConstraint(err) {
			return models.ErrConflict
		}
		return err
	}

	inserted := result.RowsAffected()
	if inserted != 1 {
		return models.ErrRowsAffected
	}

	return nil
}
