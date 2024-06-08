package models

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// Errors with scope relevant to db model management.

// ErrNotFound describes an unfound model.
var ErrNotFound error = errors.New("related model not found")

// ErrConflict describes a duplicate row insertion.
var ErrConflict error = errors.New("row insertion conflict")

// ErrRowsAffected describes an incorrect number of rows
// changed from a db mutation.
var ErrRowsAffected error = errors.New("db RowsAffected was not correct")

// ErrRelatedOrg signals that an org is missing or not Active.
var ErrRelatedOrg error = errors.New("related org is missing or not Active")

// ErrRelatedUser signals that a user is missing,
// not Active, or is in a different org.
var ErrRelatedUser error = errors.New("related user is missing, not Active, or is in a different org")

// ErrModelMigrate signals a model could not be migrated to a
// different version.
var ErrModelMigrate error = errors.New("schema version error; cannot migrate model")

// ErrDisallowedValue signals a value of the right type,
// just not allowed.
var ErrDisallowedValue error = errors.New("value disallowed in this context")

// ErrRole signals a problem with a role field.
var ErrRole error = errors.New("malformed or disallowed role")

// ErrStatus signals a problem with a status field.
var ErrStatus error = errors.New("malformed or disallowed status")

// ErrUnsafeString signals bad string input.
var ErrUnsafeString error = errors.New("string deemed unsafe")

// UniqueConstraint will try to match the db unique constraint violation.
func UniqueConstraint(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// https://www.postgresql.org/docs/current/errcodes-appendix.html
		return pgErr.Code == "23505"
	}
	return false
}

// NotNullConstraint will try to match the db not-null constraint violation.
func NotNullConstraint(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// https://www.postgresql.org/docs/current/errcodes-appendix.html
		return pgErr.Code == "23502"
	}
	return false
}
