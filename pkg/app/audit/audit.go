// package audit provides mutation recording.
package audit

import (
	"context"

	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/jackc/pgx/v5"
)

const (
	Status           = 10
	OrgInsert        = 100
	OrgOwner         = 101
	UserInsert       = 200
	UserDisplayName  = 201
	UserPassword     = 202
	UserReEncrypt    = 203
	UserAPISecret    = 204
	RepositoryInsert = 300
	RepositoryDelete = 301
)

func Insert(
	ctx context.Context,
	conn *pgx.Conn,
	code int,
	source string,
	source_id models.ID,
) error {
	const q = `insert into audit (id,code,source,source_id) values ($1,$2,$3,$4)`
	result, err := conn.Exec(ctx,
		q,
		models.NewID(),
		code,
		source,
		source_id.String())
	if err != nil {
		return err
	}

	inserted := result.RowsAffected()
	if inserted != 1 {
		return models.ErrRowsAffected
	}

	return nil
}
