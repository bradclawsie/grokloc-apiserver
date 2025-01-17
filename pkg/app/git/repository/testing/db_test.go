package testing

import (
	"context"
	"log"
	testing_ "testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/git/repository"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
)

var st *app.State

func TestRepository(t *testing_.T) {
	t.Run("InsertRead", func(t *testing_.T) {
		t.Parallel()
		r := &repository.Repository{}
		r.ID = models.NewID()
		r.Name = safe.TrustedVarChar(security.RandString())
		r.Org = models.NewID()
		r.Owner = models.NewID()
		r.Path = "/"
		r.Meta.Role = models.RoleTest
		r.Meta.Status = models.StatusActive

		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		require.NoError(t, r.Insert(context.Background(), conn.Conn()))

		// duplicate
		require.Equal(t, models.ErrConflict, r.Insert(context.Background(), conn.Conn()))

		// read
		rRead, readErr := repository.Read(context.Background(), conn.Conn(), r.ID)
		require.NoError(t, readErr)
		require.Equal(t, r.ID, rRead.ID)
		require.Equal(t, r.Name, rRead.Name)
		require.Equal(t, r.Org, rRead.Org)
		require.Equal(t, r.Owner, rRead.Owner)
		require.Equal(t, r.Path, rRead.Path)
		require.Equal(t, r.Meta.Role, rRead.Meta.Role)
		require.Equal(t, r.Meta.Status, rRead.Meta.Status)
		require.Equal(t, r.Meta.SchemaVersion, rRead.Meta.SchemaVersion)
		require.NotEqual(t, r.Meta.Ctime, rRead.Meta.Ctime)
		require.NotEqual(t, r.Meta.Mtime, rRead.Meta.Mtime)
		require.NotEqual(t, r.Meta.Signature, rRead.Meta.Signature)
	})

	t.Run("ReadMissing", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		_, readErr := repository.Read(context.Background(), conn.Conn(), models.NewID())
		require.Equal(t, models.ErrNotFound, readErr)
	})

	t.Run("Create", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		name := safe.TrustedVarChar(security.RandString())
		org := models.NewID()
		owner := models.NewID()
		path := "/"

		r, createErr := repository.Create(context.Background(), conn.Conn(), name, org, owner, path, models.RoleTest)
		require.NoError(t, createErr)

		require.Equal(t, r.Name, name)
		require.Equal(t, r.Org, org)
		require.Equal(t, r.Owner, owner)
		require.Equal(t, r.Path, path)
		require.Equal(t, r.Meta.Role, models.RoleTest)
	})

	t.Run("Delete", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		name := safe.TrustedVarChar(security.RandString())
		org := models.NewID()
		owner := models.NewID()
		path := "/"

		r, createErr := repository.Create(context.Background(), conn.Conn(), name, org, owner, path, models.RoleTest)
		require.NoError(t, createErr)
		require.NoError(t, repository.Delete(context.Background(), conn.Conn(), r.ID))
		_, readErr := repository.Read(context.Background(), conn.Conn(), r.ID)
		require.Error(t, readErr)
		require.Equal(t, models.ErrNotFound, readErr)
	})

	t.Run("DeleteMissing", func(t *testing_.T) {
		t.Parallel()
		conn, connErr := st.Master.Acquire(context.Background())
		require.NoError(t, connErr)
		defer conn.Release()

		deleteErr := repository.Delete(context.Background(), conn.Conn(), models.NewID())
		require.Error(t, deleteErr)
		require.Equal(t, models.ErrRowsAffected, deleteErr)
	})
}

func TestMain(m *testing_.M) {
	var stErr error
	st, stErr = unit.State()
	if stErr != nil {
		log.Fatal(stErr.Error())
	}
	m.Run()
}
