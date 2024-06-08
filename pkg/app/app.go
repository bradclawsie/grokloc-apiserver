package app

import (
	"errors"
	"fmt"
)

const (
	PostgresAppUrlEnvKey = "POSTGRES_APP_URL"
	RepositoryBaseEnvKey = "REPOSITORY_BASE"
)

const (
	AuthorizationHeader = "Authorization"
	IDHeader            = "X-GrokLOC-ID"
	TokenRequestHeader  = "X-GrokLOC-Token-Request"
	MaxBodySize         = 8192
)

var ErrorEnvVar = errors.New("missing or malformed environment variable")

var ErrorInadequateAuthorization = errors.New("inadequate authorization provided")

var ErrorBody = fmt.Errorf("body malformed or exceeds %v bytes", MaxBodySize)
