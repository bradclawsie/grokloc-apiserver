package security

import (
	"testing"

	"github.com/google/uuid"
	"github.com/matthewhartstonge/argon2"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type CryptSuite struct {
	suite.Suite
	Argon2Cfg argon2.Config
}

func (s *CryptSuite) SetupSuite() {
	s.Argon2Cfg = argon2.DefaultConfig()
}

func (s *CryptSuite) TestEncrypt() {
	key, err := MakeKey(uuid.NewString())
	require.Nil(s.T(), err)
	str := uuid.NewString()
	digest := EncodedSHA256(str)
	e, err := Encrypt(str, key)
	require.Nil(s.T(), err)
	d, err := Decrypt(e, digest, key)
	require.Nil(s.T(), err)
	require.Equal(s.T(), str, d)
	notKey, err := MakeKey(uuid.NewString())
	require.Nil(s.T(), err)
	_, err = Decrypt(e, digest, notKey)
	require.Error(s.T(), err)
	notDigest := EncodedSHA256(uuid.NewString())
	_, err = Decrypt(e, notDigest, key)
	require.Error(s.T(), err)
}

func (s *CryptSuite) TestDerivePassword() {
	password := RandString()
	derived, err := DerivePassword(password, s.Argon2Cfg)
	require.Nil(s.T(), err)
	good, err := VerifyPassword(password, *derived)
	require.Nil(s.T(), err)
	require.True(s.T(), good)
	bad, err := VerifyPassword(RandString(), *derived)
	require.Nil(s.T(), err)
	require.False(s.T(), bad)
}

func (s *CryptSuite) TestRandKey() {
	require.Equal(s.T(), KeyLen, len(RandKey()))
}

func TestCryptSuite(t *testing.T) {
	suite.Run(t, new(CryptSuite))
}
