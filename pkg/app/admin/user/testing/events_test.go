package testing

import (
	"encoding/json"
	"log"
	"testing"

	"github.com/google/uuid"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type EventsSuite struct {
	suite.Suite
	st *app.State
}

func (s *EventsSuite) SetupSuite() {
	var err error
	s.st, err = unit.State()
	if err != nil {
		log.Fatal(err.Error())
	}
}

func (s *EventsSuite) TestCreateEvent() {
	ev := user.CreateEvent{
		DisplayName: safe.TrustedVarChar(security.RandString()),
		Email:       safe.TrustedVarChar(security.RandString()),
		Org:         models.NewID(),
		Password:    safe.TrustedPassword(security.RandString()),
	}

	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	out, outErr := user.NewCreateEvent(&s.st.Argon2Config)
	require.NoError(s.T(), outErr)
	umErr := json.Unmarshal(bs, &out)
	require.NoError(s.T(), umErr)

	evSafe := ev
	ev.DisplayName = safe.TrustedVarChar("") // bad
	bs, bsErr = json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	out, outErr = user.NewCreateEvent(&s.st.Argon2Config)
	require.NoError(s.T(), outErr)
	umErr = json.Unmarshal(bs, &out)
	require.Error(s.T(), umErr)

	ev = evSafe
	ev.Email = safe.TrustedVarChar("") // bad
	bs, bsErr = json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	out, outErr = user.NewCreateEvent(&s.st.Argon2Config)
	require.NoError(s.T(), outErr)
	umErr = json.Unmarshal(bs, &out)
	require.Error(s.T(), umErr)

	ev = evSafe
	var empty uuid.UUID
	ev.Org = models.ID(empty)
	bs, bsErr = json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	out, outErr = user.NewCreateEvent(&s.st.Argon2Config)
	require.NoError(s.T(), outErr)
	umErr = json.Unmarshal(bs, &out)
	require.Error(s.T(), umErr)

	ev = evSafe
	ev.Password = safe.TrustedPassword("") // bad
	bs, bsErr = json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	out, outErr = user.NewCreateEvent(&s.st.Argon2Config)
	require.NoError(s.T(), outErr)
	umErr = json.Unmarshal(bs, &out)
	require.Error(s.T(), umErr)

	ev = evSafe
	out, outErr = user.NewCreateEvent(&s.st.Argon2Config)
	require.NoError(s.T(), outErr)
	// test disallowed detection
	umErr = json.Unmarshal([]byte(`{"a":"b"}`), &out)
	require.Error(s.T(), umErr)
}

func (s *EventsSuite) TestUpdateDisplayNameEvent() {
	ev := user.UpdateDisplayNameEvent{
		DisplayName: safe.TrustedVarChar(security.RandString()),
	}
	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	var out user.UpdateDisplayNameEvent
	umErr := json.Unmarshal(bs, &out)
	require.NoError(s.T(), umErr)

	ev.DisplayName = safe.TrustedVarChar("") // bad
	bs, bsErr = json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	out = user.UpdateDisplayNameEvent{}
	umErr = json.Unmarshal(bs, &out)
	require.Error(s.T(), umErr)
}

func (s *EventsSuite) TestUpdatePasswordEvent() {
	ev := user.UpdatePasswordEvent{
		Password: safe.TrustedPassword(security.RandString()),
	}
	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	var out user.UpdatePasswordEvent
	umErr := json.Unmarshal(bs, &out)
	require.NoError(s.T(), umErr)

	ev.Password = safe.TrustedPassword("") // bad
	bs, bsErr = json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	out = user.UpdatePasswordEvent{}
	umErr = json.Unmarshal(bs, &out)
	require.Error(s.T(), umErr)
}

func (s *EventsSuite) TestUpdateStatusEvent() {
	ev := user.UpdateStatusEvent{
		Status: models.StatusActive,
	}
	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	var out user.UpdateStatusEvent
	umErr := json.Unmarshal(bs, &out)
	require.NoError(s.T(), umErr)

	ev.Status = models.StatusNone // bad
	bs, bsErr = json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	out = user.UpdateStatusEvent{}
	umErr = json.Unmarshal(bs, &out)
	require.Error(s.T(), umErr)
}

func TestEventsSuite(t *testing.T) {
	suite.Run(t, new(EventsSuite))
}
