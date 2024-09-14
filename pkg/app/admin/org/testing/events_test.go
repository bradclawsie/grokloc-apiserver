package testing

import (
	"encoding/json"
	"log"
	"testing"

	"github.com/google/uuid"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
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
	ev := org.CreateEvent{
		Name:             safe.TrustedVarChar(security.RandString()),
		OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
		OwnerEmail:       safe.TrustedVarChar(security.RandString()),
		OwnerPassword:    safe.TrustedPassword(security.RandString()),
		Role:             models.RoleNormal,
	}

	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	out, outErr := org.NewCreateEvent(&s.st.Argon2Config)
	require.NoError(s.T(), outErr)
	umErr := json.Unmarshal(bs, &out)
	require.NoError(s.T(), umErr)

	evSafe := ev
	ev.Name = safe.TrustedVarChar("") // bad
	bs, bsErr = json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	out, outErr = org.NewCreateEvent(&s.st.Argon2Config)
	require.NoError(s.T(), outErr)
	umErr = json.Unmarshal(bs, &out)
	require.Error(s.T(), umErr)

	ev = evSafe
	ev.OwnerDisplayName = safe.TrustedVarChar("") // bad
	bs, bsErr = json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	out, outErr = org.NewCreateEvent(&s.st.Argon2Config)
	require.NoError(s.T(), outErr)
	umErr = json.Unmarshal(bs, &out)
	require.Error(s.T(), umErr)

	ev = evSafe
	ev.OwnerEmail = safe.TrustedVarChar("") // bad
	bs, bsErr = json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	out, outErr = org.NewCreateEvent(&s.st.Argon2Config)
	require.NoError(s.T(), outErr)
	umErr = json.Unmarshal(bs, &out)
	require.Error(s.T(), umErr)

	ev = evSafe
	ev.OwnerPassword = safe.TrustedPassword("") // bad
	bs, bsErr = json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	out, outErr = org.NewCreateEvent(&s.st.Argon2Config)
	require.NoError(s.T(), outErr)
	umErr = json.Unmarshal(bs, &out)
	require.Error(s.T(), umErr)

	ev = evSafe
	ev.Role = models.RoleNone // bad
	bs, bsErr = json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	out, outErr = org.NewCreateEvent(&s.st.Argon2Config)
	require.NoError(s.T(), outErr)
	umErr = json.Unmarshal(bs, &out)
	require.Error(s.T(), umErr)

	ev = evSafe
	out, outErr = org.NewCreateEvent(&s.st.Argon2Config)
	require.NoError(s.T(), outErr)
	// test disallowed detection
	umErr = json.Unmarshal([]byte(`{"a":"b"}`), &out)
	require.Error(s.T(), umErr)
}

func (s *EventsSuite) TestUpdateOwnerEvent() {
	ev := org.UpdateOwnerEvent{
		Owner: models.NewID(),
	}
	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	var out org.UpdateOwnerEvent
	umErr := json.Unmarshal(bs, &out)
	require.NoError(s.T(), umErr)

	var empty uuid.UUID
	ev.Owner = models.ID(empty) // bad
	bs, bsErr = json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	out = org.UpdateOwnerEvent{}
	umErr = json.Unmarshal(bs, &out)
	require.Error(s.T(), umErr)
}

func (s *EventsSuite) TestUpdateStatusEvent() {
	ev := org.UpdateStatusEvent{
		Status: models.StatusActive,
	}
	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	var out org.UpdateStatusEvent
	umErr := json.Unmarshal(bs, &out)
	require.NoError(s.T(), umErr)

	ev.Status = models.StatusNone // bad
	bs, bsErr = json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	out = org.UpdateStatusEvent{}
	umErr = json.Unmarshal(bs, &out)
	require.Error(s.T(), umErr)
}

func TestEventsSuite(t *testing.T) {
	suite.Run(t, new(EventsSuite))
}
