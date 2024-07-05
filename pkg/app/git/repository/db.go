package repository

import (
	"context"

	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/jackc/pgx/v5"
)

func (r *Repository) Insert(ctx context.Context, conn *pgx.Conn) error {
	const insertQuery = `
			insert into repositories 
			(id, name, org, owner, path, role, schema_version, status) 
			values 
			($1, $2, $3, $4, $5, $6, $7, $8)
		`

	result, err := conn.Exec(ctx, insertQuery,
		r.ID,
		r.Name,
		r.Org,
		r.Owner,
		r.Path,
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

func Read(
	ctx context.Context,
	conn *pgx.Conn,
	id models.ID,
) (*Repository, error) {
	var r Repository

	const selectQuery = `
      	select
        	name,
        	org,
        	owner,
        	path,
        	ctime,
        	mtime,
        	role,
        	schema_version,
        	signature,
        	status
      	from repositories
      	where id = $1
      	`

	selectErr := conn.QueryRow(ctx, selectQuery, id).
		Scan(&r.Name,
			&r.Org,
			&r.Owner,
			&r.Path,
			&r.Meta.Ctime,
			&r.Meta.Mtime,
			&r.Meta.Role,
			&r.Meta.SchemaVersion,
			&r.Meta.Signature,
			&r.Meta.Status,
		)
	if selectErr != nil {
		if pgx.ErrNoRows == selectErr {
			return nil, models.ErrNotFound
		}
		return nil, selectErr
	}

	// mismatch schema versions require migration
	if SchemaVersion != r.Meta.SchemaVersion {
		migrated := false
		// put migration code here

		if !migrated {
			return nil, models.ErrModelMigrate
		}
	}

	r.ID = id

	return &r, nil
}
