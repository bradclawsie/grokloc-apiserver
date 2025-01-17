package testing

import (
	"context"
	testing_ "testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app/audit"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
)

func TestAudit(t *testing_.T) {
	t.Run("Insert", func(t *testing_.T) {
		t.Parallel()
		st, stErr := unit.State()
		defer func() {
			_ = st.Close()
		}()
		require.NoError(t, stErr)
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()
		err := audit.Insert(
			context.Background(),
			conn.Conn(),
			audit.UserInsert,
			security.RandString(),
			models.NewID(),
		)
		require.Nil(t, err)
	})
}
