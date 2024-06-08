// Package jwt provides token functionality.
package jwt

import (
	"errors"
	"strings"
	"time"

	go_jwt "github.com/golang-jwt/jwt/v5"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
)

// Expiration is offset from current time.
const Expiration = 86400

// AuthorizationType is a prefix for the signed JWT.
const AuthorizationType = "Bearer"

var ErrIncorrectSigningMethod = errors.New("signing method not HS256")

// EncodeTokenRequest creates a string used to make a token request.
// The caller must perform this exact string construction using
// their user ID and api secret.
func EncodeTokenRequest(userID models.ID, userAPISecret string) string {
	return security.EncodedSHA256(userID.String() + userAPISecret)
}

// VerifyTokenRequest confirms that `tokenRequest` matches the
// user ID and api secret.
func VerifyTokenRequest(userID models.ID, userAPISecret string, tokenRequest string) bool {
	return EncodeTokenRequest(userID, userAPISecret) == tokenRequest
}

// NewToken returns a signed jwt.
// The sub field uses the tokenRequest as created by EncodeTokenRequest
// and verified by VerifyTokenRequest. This allows for checking if
// the scoped user's APISecret has changed later on (which would
// make it impossible to recreate tokenRequest for comparison).
func New(tokenRequest string, signingKey []byte) (string, error) {
	now := time.Now().Unix()
	tok := go_jwt.NewWithClaims(go_jwt.SigningMethodHS256, go_jwt.MapClaims{
		"iss": "GrokLOC.com",
		"sub": tokenRequest,
		"nbf": now,
		"iat": now,
		"exp": now + Expiration,
	})
	return tok.SignedString(signingKey)
}

// Decode takes the string returned by `Encode` and decodes the token.
func Decode(tokenStr string, signingKey []byte) (*go_jwt.Token, error) {
	return go_jwt.Parse(tokenStr,
		func(token *go_jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*go_jwt.SigningMethodHMAC); !ok {
				return nil, ErrIncorrectSigningMethod
			}
			return signingKey, nil
		})
}

// SignedStringToHeaderValue produces the value for the Authorization header.
func SignedStringToHeaderValue(signedString string) string {
	return AuthorizationType + " " + signedString
}

func HeaderValueToSignedString(headerValue string) (string, error) {
	authorizationType, signedString, found := strings.Cut(headerValue, " ")
	if !found || authorizationType != AuthorizationType || len(signedString) == 0 {
		return "", errors.New("malformed header value")
	}
	return signedString, nil
}
