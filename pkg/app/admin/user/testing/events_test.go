package testing

import (
	"encoding/json"
	testing_ "testing"

	"github.com/google/uuid"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
)

func TestEvents(t *testing_.T) {
	t.Run("CreateEvent", func(t *testing_.T) {
		t.Parallel()
		ev := user.CreateEvent{
			DisplayName: safe.TrustedVarChar(security.RandString()),
			Email:       safe.TrustedVarChar(security.RandString()),
			Org:         models.NewID(),
			Password:    safe.TrustedPassword(security.RandString()),
		}

		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		out, outErr := user.NewCreateEvent(&st.Argon2Config)
		require.NoError(t, outErr)
		umErr := json.Unmarshal(bs, &out)
		require.NoError(t, umErr)

		evSafe := ev
		ev.DisplayName = safe.TrustedVarChar("") // bad
		bs, bsErr = json.Marshal(ev)
		require.NoError(t, bsErr)
		out, outErr = user.NewCreateEvent(&st.Argon2Config)
		require.NoError(t, outErr)
		umErr = json.Unmarshal(bs, &out)
		require.Error(t, umErr)

		ev = evSafe
		ev.Email = safe.TrustedVarChar("") // bad
		bs, bsErr = json.Marshal(ev)
		require.NoError(t, bsErr)
		out, outErr = user.NewCreateEvent(&st.Argon2Config)
		require.NoError(t, outErr)
		umErr = json.Unmarshal(bs, &out)
		require.Error(t, umErr)

		ev = evSafe
		var empty uuid.UUID
		ev.Org = models.ID(empty)
		bs, bsErr = json.Marshal(ev)
		require.NoError(t, bsErr)
		out, outErr = user.NewCreateEvent(&st.Argon2Config)
		require.NoError(t, outErr)
		umErr = json.Unmarshal(bs, &out)
		require.Error(t, umErr)

		ev = evSafe
		ev.Password = safe.TrustedPassword("") // bad
		bs, bsErr = json.Marshal(ev)
		require.NoError(t, bsErr)
		out, outErr = user.NewCreateEvent(&st.Argon2Config)
		require.NoError(t, outErr)
		umErr = json.Unmarshal(bs, &out)
		require.Error(t, umErr)

		ev = evSafe
		out, outErr = user.NewCreateEvent(&st.Argon2Config)
		require.NoError(t, outErr)
		// test disallowed detection
		umErr = json.Unmarshal([]byte(`{"a":"b"}`), &out)
		require.Error(t, umErr)
	})

	t.Run("UpdateDisplayNameEvent", func(t *testing_.T) {
		t.Parallel()
		ev := user.UpdateDisplayNameEvent{
			DisplayName: safe.TrustedVarChar(security.RandString()),
		}
		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		var out user.UpdateDisplayNameEvent
		umErr := json.Unmarshal(bs, &out)
		require.NoError(t, umErr)

		ev.DisplayName = safe.TrustedVarChar("") // bad
		bs, bsErr = json.Marshal(ev)
		require.NoError(t, bsErr)
		out = user.UpdateDisplayNameEvent{}
		umErr = json.Unmarshal(bs, &out)
		require.Error(t, umErr)
	})

	t.Run("UpdatePasswordEvent", func(t *testing_.T) {
		t.Parallel()
		ev := user.UpdatePasswordEvent{
			Password: safe.TrustedPassword(security.RandString()),
		}
		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		var out user.UpdatePasswordEvent
		umErr := json.Unmarshal(bs, &out)
		require.NoError(t, umErr)

		ev.Password = safe.TrustedPassword("") // bad
		bs, bsErr = json.Marshal(ev)
		require.NoError(t, bsErr)
		out = user.UpdatePasswordEvent{}
		umErr = json.Unmarshal(bs, &out)
		require.Error(t, umErr)
	})

	t.Run("UpdateStatusEvent", func(t *testing_.T) {
		t.Parallel()
		ev := user.UpdateStatusEvent{
			Status: models.StatusActive,
		}
		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		var out user.UpdateStatusEvent
		umErr := json.Unmarshal(bs, &out)
		require.NoError(t, umErr)

		ev.Status = models.StatusNone // bad
		bs, bsErr = json.Marshal(ev)
		require.NoError(t, bsErr)
		out = user.UpdateStatusEvent{}
		umErr = json.Unmarshal(bs, &out)
		require.Error(t, umErr)
	})
}
