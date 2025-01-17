package security

import (
	testing_ "testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestVersionKey(t *testing_.T) {
	t.Run("OK", func(t *testing_.T) {
		t.Parallel()
		id0 := uuid.New()
		k0 := RandKey()
		id1 := uuid.New()
		k1 := RandKey()
		keyMap := map[uuid.UUID][]byte{
			id0: k0,
			id1: k1,
		}
		v, newErr := NewVersionKey(KeyMap(keyMap), id0)
		require.NoError(t, newErr)
		kGet, getErr := v.Get(id1)
		require.NoError(t, getErr)
		require.Equal(t, k1, kGet)
		versionCurrent, kCurrent, currentErr := v.GetCurrent()
		require.NoError(t, currentErr)
		require.Equal(t, id0, versionCurrent)
		require.Equal(t, k0, kCurrent)
	})

	t.Run("MissingCurrent", func(t *testing_.T) {
		t.Parallel()
		keyMap := map[uuid.UUID][]byte{
			uuid.New(): RandKey(),
			uuid.New(): RandKey(),
		}
		_, err := NewVersionKey(KeyMap(keyMap), uuid.New())
		require.Equal(t, ErrCurrentKeyNotFound, err)
	})
}
