package unit

import (
	"context"
	testing_ "testing"

	"github.com/stretchr/testify/require"
)

func TestUnit(t *testing_.T) {
	t.Run("State", func(t *testing_.T) {
		t.Parallel()
		st, stErr := State()
		defer func() {
			_ = st.Close()
		}()
		require.NoError(t, stErr)
		ctx := context.Background()
		conn, connErr := st.Master.Acquire(ctx)
		require.NoError(t, connErr)
		defer conn.Release()
		var count int32
		selectErr := conn.QueryRow(ctx, `select count(*) from orgs`).Scan(&count)
		require.NoError(t, selectErr)
		require.True(t, true)
	})
}
