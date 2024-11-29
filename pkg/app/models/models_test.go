package models

import (
	"encoding/json"
	"fmt"
	testing_ "testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestModels(t *testing_.T) {
	t.Run("BaseJSON", func(t *testing_.T) {
		t.Parallel()
		m := Meta{
			Ctime:         time.Now().Unix(),
			Mtime:         time.Now().Unix(),
			Role:          RoleTest,
			SchemaVersion: 2,
			Signature:     uuid.New(),
			Status:        StatusActive,
		}
		base := Base{ID: NewID(), Meta: m}
		bs, err := json.Marshal(base)
		require.NoError(t, err)
		var baseOut Base
		err = json.Unmarshal(bs, &baseOut)
		require.NoError(t, err)
		require.Equal(t, base.ID, baseOut.ID)
		require.Equal(t, m, baseOut.Meta)
		require.Equal(t, RoleTest, baseOut.Meta.Role)
	})

	t.Run("Role", func(t *testing_.T) {
		t.Parallel()
		role, err := NewRole(int64(RoleNone))
		require.Error(t, err)
		require.Equal(t, RoleNone, role)
		role, err = NewRole(int64(RoleNormal))
		require.NoError(t, err)
		require.Equal(t, RoleNormal, role)
		role, err = NewRole(int64(RoleAdmin))
		require.NoError(t, err)
		require.Equal(t, RoleAdmin, role)
		role, err = NewRole(int64(RoleTest))
		require.NoError(t, err)
		require.Equal(t, RoleTest, role)
		type T struct {
			R Role `json:"role"`
		}
		c := T{R: RoleTest}
		bs, err := json.Marshal(c)
		require.NoError(t, err)
		out := &T{}
		err = json.Unmarshal(bs, out)
		require.NoError(t, err)
		require.Equal(t, c.R, out.R)
		c.R = RoleNone // invalid
		bs, err = json.Marshal(c)
		require.NoError(t, err)
		out = &T{}
		err = json.Unmarshal(bs, out)
		require.Error(t, err)
	})

	t.Run("Status", func(t *testing_.T) {
		t.Parallel()
		status, err := NewStatus(int64(StatusNone))
		require.Error(t, err)
		require.Equal(t, StatusNone, status)
		status, err = NewStatus(int64(StatusUnconfirmed))
		require.NoError(t, err)
		require.Equal(t, StatusUnconfirmed, status)
		status, err = NewStatus(int64(StatusActive))
		require.NoError(t, err)
		require.Equal(t, StatusActive, status)
		status, err = NewStatus(int64(StatusInactive))
		require.NoError(t, err)
		require.Equal(t, StatusInactive, status)
		type T struct {
			S Status `json:"status"`
		}
		c := T{S: StatusActive}
		bs, err := json.Marshal(c)
		require.NoError(t, err)
		out := &T{}
		err = json.Unmarshal(bs, out)
		require.NoError(t, err)
		require.Equal(t, c.S, out.S)
		c.S = StatusNone // invalid
		bs, err = json.Marshal(c)
		require.NoError(t, err)
		out = &T{}
		err = json.Unmarshal(bs, out)
		require.Error(t, err)
	})

	t.Run("ID", func(t *testing_.T) {
		t.Parallel()
		id := new(ID)
		require.Error(t, id.Scan("not an id"))
		require.NoError(t, id.Scan(fmt.Sprintf("%v", NewID())))
	})
}
