package safe

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type StringSuite struct {
	suite.Suite
}

func (s *StringSuite) TestStringIs() {
	require.Equal(s.T(), ErrStringLength, StringIs(""))
	require.Equal(s.T(), ErrCharsDetected, StringIs("hello'"))
	require.Equal(s.T(), ErrCharsDetected, StringIs("hello`"))
	require.NoError(s.T(), StringIs("hello"))

	for _, v := range []string{
		"insert ",
		"update ",
		"upsert ",
		"drop ",
		"create ",
	} {
		require.Equal(s.T(), ErrSQLDetected, StringIs(fmt.Sprintf("%s ", v)))
		require.Equal(s.T(), ErrSQLDetected, StringIs(fmt.Sprintf(" %s ", v)))
		require.Equal(s.T(), ErrSQLDetected, StringIs(fmt.Sprintf("%s ", strings.ToUpper(v))))
	}
	require.Equal(s.T(), ErrCharsDetected, StringIs(" < "))
	require.Equal(s.T(), ErrCharsDetected, StringIs(" > "))
	require.Equal(s.T(), ErrHTMLDetected, StringIs("&gt;"))
	require.Equal(s.T(), ErrHTMLDetected, StringIs("&lt;"))
	require.Equal(s.T(), ErrHTMLDetected, StringIs("window.onload"))
	require.Equal(s.T(), ErrWSDetected, StringIs(`
                                      multi
                                      line
                                     `))
	require.Equal(s.T(), ErrWSDetected, StringIs("\thello\t"))
}

func (s *StringSuite) TestEmptyVarChar() {
	_, err := NewVarChar("")
	require.Error(s.T(), err)
}

func (s *StringSuite) TestJSON() {
	type T struct {
		S VarChar `json:"s"`
	}
	t := T{S: TrustedVarChar("hello")}
	bs, err := json.Marshal(t)
	require.NoError(s.T(), err)
	require.Equal(s.T(), `{"s":"hello"}`, string(bs))
	out := &T{}
	err = json.Unmarshal(bs, out)
	require.NoError(s.T(), err)
	// this fails because s is empty
	require.Error(s.T(), json.Unmarshal([]byte(`{"s":""}`), &T{}))
}

func TestStringSuite(t *testing.T) {
	suite.Run(t, new(StringSuite))
}
