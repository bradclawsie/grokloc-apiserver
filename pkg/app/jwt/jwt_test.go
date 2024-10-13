package jwt

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
)

type JWTSuite struct {
	suite.Suite
}

func (s *JWTSuite) TestEncodeDecode() {
	id := models.NewID()
	apiSecret := models.NewID().String()
	signingKey := security.RandKey()
	signedToken, signErr := New(EncodeTokenRequest(id, apiSecret), signingKey)
	require.NoError(s.T(), signErr)
	token, tokenErr := Decode(signedToken, signingKey)
	require.NoError(s.T(), tokenErr)
	require.True(s.T(), token.Valid)
	sub, subErr := token.Claims.GetSubject()
	require.NoError(s.T(), subErr)
	require.Equal(s.T(), EncodeTokenRequest(id, apiSecret), sub)
}

func (s *JWTSuite) TestHeaderValue() {
	id := models.NewID()
	apiSecret := models.NewID().String()
	signingKey := security.RandKey()
	signedToken, signErr := New(EncodeTokenRequest(id, apiSecret), signingKey)
	require.NoError(s.T(), signErr)
	headerValue := SignedStringToHeaderValue(signedToken)
	extracted, err := HeaderValueToSignedString(headerValue)
	require.NoError(s.T(), err)
	require.Equal(s.T(), signedToken, extracted)
}

func TestJWTSuite(t *testing.T) {
	suite.Run(t, new(JWTSuite))
}
