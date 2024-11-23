package client

import (
	testing_ "testing"

	"github.com/stretchr/testify/require"
)

func TestClient(t *testing_.T) {
	t.Run("OK", func(t *testing_.T) {
		t.Parallel()
		require.NoError(t, rootClient.OK())
		require.NoError(t, orgOwnerClient.OK())
		require.NoError(t, regularUserClient.OK())
	})

	t.Run("AuthOK", func(t *testing_.T) {
		t.Parallel()
		require.NoError(t, rootClient.AuthOK())
		require.NoError(t, orgOwnerClient.AuthOK())
		require.NoError(t, regularUserClient.AuthOK())
	})
}
