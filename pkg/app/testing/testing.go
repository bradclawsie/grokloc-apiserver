// Package testing provides test utility functions.
package testing

import (
	"context"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/jackc/pgx/v5"
)

// TestOrgAndUser creates a new test org, an owner, and a non-owner user.
func TestOrgAndUser(conn *pgx.Conn, st *app.State) (*org.Org, *user.User, *user.User, error) {
	orgName := safe.TrustedVarChar(security.RandString())
	ownerDisplayName := safe.TrustedVarChar(security.RandString())
	ownerEmail := safe.TrustedVarChar(security.RandString())
	ownerPassword, ownerPasswordErr := security.DerivePassword(security.RandString(), st.Argon2Config)
	if ownerPasswordErr != nil {
		return nil, nil, nil, ownerPasswordErr
	}

	o, owner, orgCreateErr := org.Create(context.Background(),
		conn,
		orgName,
		ownerDisplayName,
		ownerEmail,
		*ownerPassword,
		models.RoleTest,
		st.VersionKey)

	if orgCreateErr != nil {
		return nil, nil, nil, orgCreateErr
	}

	displayName := safe.TrustedVarChar(security.RandString())
	email := safe.TrustedVarChar(security.RandString())
	password, passwordErr := security.DerivePassword(security.RandString(), st.Argon2Config)
	if passwordErr != nil {
		return nil, nil, nil, passwordErr
	}

	u, uCreateErr := user.Create(context.Background(),
		conn,
		displayName,
		email,
		o.ID,
		*password,
		st.VersionKey,
	)
	if uCreateErr != nil {
		return nil, nil, nil, uCreateErr
	}

	updateErr := u.UpdateStatus(context.Background(), conn, st.VersionKey, models.StatusActive)
	if updateErr != nil {
		return nil, nil, nil, updateErr
	}

	return o, owner, u, nil
}
