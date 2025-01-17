package jwt

import (
	testing_ "testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
)

func TestJWT(t *testing_.T) {
	t.Run("EncodeDecode", func(t *testing_.T) {
		t.Parallel()
		id := models.NewID()
		apiSecret := models.NewID().String()
		signingKey := security.RandKey()
		signedToken, signErr := New(EncodeTokenRequest(id, apiSecret), signingKey)
		require.NoError(t, signErr)
		token, tokenErr := Decode(signedToken, signingKey)
		require.NoError(t, tokenErr)
		require.True(t, token.Valid)
		sub, subErr := token.Claims.GetSubject()
		require.NoError(t, subErr)
		require.Equal(t, EncodeTokenRequest(id, apiSecret), sub)
	})

	t.Run("HeaderValue", func(t *testing_.T) {
		t.Parallel()
		id := models.NewID()
		apiSecret := models.NewID().String()
		signingKey := security.RandKey()
		signedToken, signErr := New(EncodeTokenRequest(id, apiSecret), signingKey)
		require.NoError(t, signErr)
		headerValue := SignedStringToHeaderValue(signedToken)
		extracted, err := HeaderValueToSignedString(headerValue)
		require.NoError(t, err)
		require.Equal(t, signedToken, extracted)
	})
}
