package app

import (
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/env"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matthewhartstonge/argon2"
)

// State contains all references and values that must be
// available for the duration of an app run.
type State struct {
	// Level describes the environment the State is set in
	Level env.Level

	// Logger is the default state logger
	Logger *slog.Logger

	// APIVersion is the expected runtime supported api version
	APIVersion string

	// Master is a pool of conns to the master db
	Master *pgxpool.Pool

	// Replicas is a pool of conns to the replica dbs
	Replicas []*pgxpool.Pool

	// ConnTimeout is a timeout to acquire a db conn
	ConnTimeout time.Duration

	// ExecTimeout is a timeout for executing a db query
	ExecTimeout time.Duration

	// Argon2Config for password hashing
	Argon2Config argon2.Config

	// RepositoryBase is the path where checked out repos are found
	RepositoryBase string

	// SigningKey signs JWTs
	SigningKey []byte

	// VersionKey maps key ids to database encryption keys
	VersionKey *security.VersionKey

	// DefaultRole is the environment role default for models instance
	DefaultRole models.Role

	// Root user
	Root *user.User

	// Root org
	Org *org.Org
}

// RandomReplica selects a random replica.
func (s *State) RandomReplica() *pgxpool.Pool {
	l := len(s.Replicas)
	if l == 0 {
		panic("no replicas")
	}
	return s.Replicas[rand.IntN(l)]
}

// Close performs any post-use tasks.
func (s *State) Close() error {
	if s.Level == env.Unit {
		if s.Master != nil {
			s.Master.Close()
		}
		return nil
	}
	return errors.New("unhandled level")
}
