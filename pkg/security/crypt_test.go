package security

import (
	testing_ "testing"

	"github.com/google/uuid"
	"github.com/matthewhartstonge/argon2"
	"github.com/stretchr/testify/require"
)

func TestCrypt(t *testing_.T) {
	t.Run("Encrypt", func(t *testing_.T) {
		t.Parallel()
		key, err := MakeKey(uuid.NewString())
		require.Nil(t, err)
		str := uuid.NewString()
		digest := EncodedSHA256(str)
		e, err := Encrypt(str, key)
		require.Nil(t, err)
		d, err := Decrypt(e, digest, key)
		require.Nil(t, err)
		require.Equal(t, str, d)
		notKey, err := MakeKey(uuid.NewString())
		require.Nil(t, err)
		_, err = Decrypt(e, digest, notKey)
		require.Error(t, err)
		notDigest := EncodedSHA256(uuid.NewString())
		_, err = Decrypt(e, notDigest, key)
		require.Error(t, err)
	})

	t.Run("DerivePassword", func(t *testing_.T) {
		t.Parallel()
		password := RandString()
		derived, err := DerivePassword(password, argon2.DefaultConfig())
		require.Nil(t, err)
		good, err := VerifyPassword(password, *derived)
		require.Nil(t, err)
		require.True(t, good)
		bad, err := VerifyPassword(RandString(), *derived)
		require.Nil(t, err)
		require.False(t, bad)
	})
}
