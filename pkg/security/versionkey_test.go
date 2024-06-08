package security

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type VersionKeySuite struct {
	suite.Suite
}

func (s *VersionKeySuite) TestVersionKeyOK() {
	id0 := uuid.New()
	k0 := RandKey()
	id1 := uuid.New()
	k1 := RandKey()
	keyMap := map[uuid.UUID][]byte{
		id0: k0,
		id1: k1,
	}
	v, newErr := NewVersionKey(KeyMap(keyMap), id0)
	require.NoError(s.T(), newErr)
	kGet, getErr := v.Get(id1)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), k1, kGet)
	versionCurrent, kCurrent, currentErr := v.GetCurrent()
	require.NoError(s.T(), currentErr)
	require.Equal(s.T(), id0, versionCurrent)
	require.Equal(s.T(), k0, kCurrent)
}

func (s *VersionKeySuite) TestVersionKeyMissingCurrentError() {
	keyMap := map[uuid.UUID][]byte{
		uuid.New(): RandKey(),
		uuid.New(): RandKey(),
	}
	_, err := NewVersionKey(KeyMap(keyMap), uuid.New())
	require.Equal(s.T(), ErrCurrentKeyNotFound, err)
}

func TestVersionKeySuite(t *testing.T) {
	suite.Run(t, new(VersionKeySuite))
}
