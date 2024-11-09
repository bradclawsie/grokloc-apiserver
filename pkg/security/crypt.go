package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/matthewhartstonge/argon2"
)

// ErrDigest signals a checksum mismatch.
var ErrDigest = errors.New("value does not have correct digest")

// ErrNonce signals a failure to construct the nonce.
var ErrNonce = errors.New("nonce could not be constructed")

// EncodedSHA256 returns the encoded (base16) sha256sums.
func EncodedSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// MakeKey returns a 32-len byte slice.
func MakeKey(s string) ([]byte, error) {
	v := EncodedSHA256(s)
	bs := []byte(v[:KeyLen])
	if len(bs) != KeyLen {
		return nil, errors.New("cannot construct key")
	}
	return bs, nil
}

// RandKey returns a new random key.
//
// see panic on failure
func RandKey() []byte {
	bs := make([]byte, KeyLen)
	_, err := io.ReadFull(rand.Reader, bs)
	if err != nil {
		panic(err)
	}
	return bs
}

// RandString is a RandKey wrapped in a hex-encoded sha256.
func RandString() string {
	k := RandKey()
	sum := sha256.Sum256([]byte(k))
	return hex.EncodeToString(sum[:])
}

// Encrypt returns the hex-encoded AES symmetric encryption
// of s with key.
func Encrypt(s string, key []byte) (string, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(gcm.Seal(nonce, nonce, []byte(s), nil)), nil
}

// Decrypt reverses Encrypt.
// `e` is the crypted+encoded string returned by `encrypt`.
func Decrypt(e, expected_sha256 string, key []byte) (string, error) {
	d, err := hex.DecodeString(e)
	if err != nil {
		return "", err
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(d) < nonceSize {
		return "", ErrNonce
	}
	nonce, msg := d[:nonceSize], d[nonceSize:]
	bs, err := gcm.Open(nil, nonce, msg, nil) // #nosec G407
	if err != nil {
		return "", err
	}
	s := string(bs)
	if EncodedSHA256(s) != expected_sha256 {
		return "", ErrDigest
	}
	return s, nil
}

// DerivePassword performs a one-way hash on a password using argon2.
func DerivePassword(password string, cfg argon2.Config) (*safe.Password, error) {
	raw, err := cfg.Hash([]byte(password), nil)
	if err != nil {
		return nil, err
	}
	return safe.NewPassword(string(raw.Encode()))
}

// VerifyPassword returns true if guess is the same as the password
// forming `derived`.
func VerifyPassword(guess string, derived safe.Password) (bool, error) {
	return argon2.VerifyEncoded([]byte(guess), []byte(derived.String()))
}
