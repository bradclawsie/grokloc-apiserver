package env

import (
	testing_ "testing"

	"github.com/stretchr/testify/require"
)

func TestEnv(t *testing_.T) {
	t.Run("Types", func(t *testing_.T) {
		t.Parallel()
		var err error
		var level Level
		_, err = NewLevel("")
		require.Error(t, err)
		level, err = NewLevel("UNIT")
		require.NoError(t, err)
		require.Equal(t, Unit, level)
	})
}
