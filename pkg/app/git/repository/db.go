package repository

import (
	"context"

	"github.com/grokloc/grokloc-apiserver/pkg/app/audit"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
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

func Create(
	ctx context.Context,
	conn *pgx.Conn,
	name safe.VarChar,
	org models.ID,
	owner models.ID,
	path string,
	role models.Role,
) (*Repository, error) {
	r := &Repository{Name: name, Org: org, Owner: owner, Path: path}
	r.ID = models.NewID()
	r.Meta.Role = role
	r.Meta.Status = models.StatusActive
	r.Meta.SchemaVersion = SchemaVersion

	tx, txErr := conn.Begin(ctx)
	if txErr != nil {
		return nil, txErr
	}
	defer tx.Rollback(ctx) // nolint:errcheck

	insertErr := r.Insert(ctx, tx.Conn())
	if insertErr != nil {
		return nil, insertErr
	}

	auditErr := audit.Insert(ctx, tx.Conn(), audit.RepositoryInsert, "repositories", r.ID)
	if auditErr != nil {
		return nil, auditErr
	}

	commitErr := tx.Commit(ctx)
	if commitErr != nil {
		return nil, commitErr
	}

	return Read(ctx, conn, r.ID)
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

// Delete actually deletes a row - unlike other models that merely leave
// a row as not active. Since a repositories row represents a real git
// repository that can be deleted, the row should be deleted also.
func Delete(
	ctx context.Context,
	conn *pgx.Conn,
	id models.ID,
) error {
	const deleteQuery = `
			delete from repositories where id = $1
		`

	tx, txErr := conn.Begin(ctx)
	if txErr != nil {
		return txErr
	}
	defer tx.Rollback(ctx) // nolint:errcheck

	result, err := conn.Exec(ctx, deleteQuery, id)
	if err != nil {
		return err
	}

	deleted := result.RowsAffected()
	if deleted != 1 {
		return models.ErrRowsAffected
	}

	auditErr := audit.Insert(ctx, tx.Conn(), audit.RepositoryDelete, "repositories", id)
	if auditErr != nil {
		return auditErr
	}

	return tx.Commit(ctx)
}
