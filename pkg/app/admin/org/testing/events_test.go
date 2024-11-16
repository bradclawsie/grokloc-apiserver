package testing

import (
	"encoding/json"
	testing_ "testing"

	"github.com/google/uuid"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
)

func TestEvents(t *testing_.T) {
	t.Run("CreateEvent", func(t *testing_.T) {
		t.Parallel()
		ev := org.CreateEvent{
			Name:             safe.TrustedVarChar(security.RandString()),
			OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
			OwnerEmail:       safe.TrustedVarChar(security.RandString()),
			OwnerPassword:    safe.TrustedPassword(security.RandString()),
			Role:             models.RoleNormal,
		}

		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		out, outErr := org.NewCreateEvent(&st.Argon2Config)
		require.NoError(t, outErr)
		umErr := json.Unmarshal(bs, &out)
		require.NoError(t, umErr)

		evSafe := ev
		ev.Name = safe.TrustedVarChar("") // bad
		bs, bsErr = json.Marshal(ev)
		require.NoError(t, bsErr)
		out, outErr = org.NewCreateEvent(&st.Argon2Config)
		require.NoError(t, outErr)
		umErr = json.Unmarshal(bs, &out)
		require.Error(t, umErr)

		ev = evSafe
		ev.OwnerDisplayName = safe.TrustedVarChar("") // bad
		bs, bsErr = json.Marshal(ev)
		require.NoError(t, bsErr)
		out, outErr = org.NewCreateEvent(&st.Argon2Config)
		require.NoError(t, outErr)
		umErr = json.Unmarshal(bs, &out)
		require.Error(t, umErr)

		ev = evSafe
		ev.OwnerEmail = safe.TrustedVarChar("") // bad
		bs, bsErr = json.Marshal(ev)
		require.NoError(t, bsErr)
		out, outErr = org.NewCreateEvent(&st.Argon2Config)
		require.NoError(t, outErr)
		umErr = json.Unmarshal(bs, &out)
		require.Error(t, umErr)

		ev = evSafe
		ev.OwnerPassword = safe.TrustedPassword("") // bad
		bs, bsErr = json.Marshal(ev)
		require.NoError(t, bsErr)
		out, outErr = org.NewCreateEvent(&st.Argon2Config)
		require.NoError(t, outErr)
		umErr = json.Unmarshal(bs, &out)
		require.Error(t, umErr)

		ev = evSafe
		ev.Role = models.RoleNone // bad
		bs, bsErr = json.Marshal(ev)
		require.NoError(t, bsErr)
		out, outErr = org.NewCreateEvent(&st.Argon2Config)
		require.NoError(t, outErr)
		umErr = json.Unmarshal(bs, &out)
		require.Error(t, umErr)

		ev = evSafe
		out, outErr = org.NewCreateEvent(&st.Argon2Config)
		require.NoError(t, outErr)
		// test disallowed detection
		umErr = json.Unmarshal([]byte(`{"a":"b"}`), &out)
		require.Error(t, umErr)
	})

	t.Run("UpdateOwnerEvent", func(t *testing_.T) {
		t.Parallel()
		ev := org.UpdateOwnerEvent{
			Owner: models.NewID(),
		}
		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		var out org.UpdateOwnerEvent
		umErr := json.Unmarshal(bs, &out)
		require.NoError(t, umErr)

		var empty uuid.UUID
		ev.Owner = models.ID(empty) // bad
		bs, bsErr = json.Marshal(ev)
		require.NoError(t, bsErr)
		out = org.UpdateOwnerEvent{}
		umErr = json.Unmarshal(bs, &out)
		require.Error(t, umErr)
	})

	t.Run("UpdateStatusEvent", func(t *testing_.T) {
		t.Parallel()
		ev := org.UpdateStatusEvent{
			Status: models.StatusActive,
		}
		bs, bsErr := json.Marshal(ev)
		require.NoError(t, bsErr)
		var out org.UpdateStatusEvent
		umErr := json.Unmarshal(bs, &out)
		require.NoError(t, umErr)

		ev.Status = models.StatusNone // bad
		bs, bsErr = json.Marshal(ev)
		require.NoError(t, bsErr)
		out = org.UpdateStatusEvent{}
		umErr = json.Unmarshal(bs, &out)
		require.Error(t, umErr)
	})
}
