package models

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ModelsSuite struct {
	suite.Suite
}

func (s *ModelsSuite) TestBaseJSON() {
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
	require.NoError(s.T(), err)
	var baseOut Base
	err = json.Unmarshal(bs, &baseOut)
	require.NoError(s.T(), err)
	require.Equal(s.T(), base.ID, baseOut.ID)
	require.Equal(s.T(), m, baseOut.Meta)
	require.Equal(s.T(), RoleTest, baseOut.Meta.Role)
}

func (s *ModelsSuite) TestRole() {
	role, err := NewRole(int64(RoleNone))
	require.Error(s.T(), err)
	require.Equal(s.T(), RoleNone, role)

	role, err = NewRole(int64(RoleNormal))
	require.NoError(s.T(), err)
	require.Equal(s.T(), RoleNormal, role)

	role, err = NewRole(int64(RoleAdmin))
	require.NoError(s.T(), err)
	require.Equal(s.T(), RoleAdmin, role)

	role, err = NewRole(int64(RoleTest))
	require.NoError(s.T(), err)
	require.Equal(s.T(), RoleTest, role)

	// round trip json to test unmarshal
	type T struct {
		R Role `json:"role"`
	}
	t := T{R: RoleTest}
	bs, err := json.Marshal(t)
	require.NoError(s.T(), err)
	out := &T{}
	err = json.Unmarshal(bs, out)
	require.NoError(s.T(), err)
	require.Equal(s.T(), t.R, out.R)

	// RoleNone means it is an invalid role, unmarshal should fail
	t.R = RoleNone
	bs, err = json.Marshal(t)
	require.NoError(s.T(), err)
	out = &T{}
	err = json.Unmarshal(bs, out)
	require.Error(s.T(), err)
}

func (s *ModelsSuite) TestStatus() {
	status, err := NewStatus(int64(StatusNone))
	require.Error(s.T(), err)
	require.Equal(s.T(), StatusNone, status)

	status, err = NewStatus(int64(StatusUnconfirmed))
	require.NoError(s.T(), err)
	require.Equal(s.T(), StatusUnconfirmed, status)

	status, err = NewStatus(int64(StatusActive))
	require.NoError(s.T(), err)
	require.Equal(s.T(), StatusActive, status)

	status, err = NewStatus(int64(StatusInactive))
	require.NoError(s.T(), err)
	require.Equal(s.T(), StatusInactive, status)

	// round trip json to test unmarshal
	type T struct {
		S Status `json:"status"`
	}
	t := T{S: StatusActive}
	bs, err := json.Marshal(t)
	require.NoError(s.T(), err)
	out := &T{}
	err = json.Unmarshal(bs, out)
	require.NoError(s.T(), err)
	require.Equal(s.T(), t.S, out.S)

	// StatusNone means it is an invalid status, unmarshal should fail
	t.S = StatusNone
	bs, err = json.Marshal(t)
	require.NoError(s.T(), err)
	out = &T{}
	err = json.Unmarshal(bs, out)
	require.Error(s.T(), err)
}

func (s *ModelsSuite) TestID() {
	id := new(ID)
	require.Error(s.T(), id.Scan("not an id"))
	require.NoError(s.T(), id.Scan(fmt.Sprintf("%v", NewID())))
}

func TestModelsSuite(t *testing.T) {
	suite.Run(t, new(ModelsSuite))
}
