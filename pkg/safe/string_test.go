package safe

import (
	"encoding/json"
	"fmt"
	"strings"
	testing_ "testing"

	"github.com/stretchr/testify/require"
)

func TestString(t *testing_.T) {
	t.Run("Safe", func(t *testing_.T) {
		t.Parallel()
		require.Equal(t, ErrStringLength, StringIs(""))
		require.Equal(t, ErrCharsDetected, StringIs("hello'"))
		require.Equal(t, ErrCharsDetected, StringIs("hello`"))
		require.NoError(t, StringIs("hello"))
		for _, v := range []string{
			"insert ",
			"update ",
			"upsert ",
			"drop ",
			"create ",
		} {
			require.Equal(t, ErrSQLDetected, StringIs(fmt.Sprintf("%s ", v)))
			require.Equal(t, ErrSQLDetected, StringIs(fmt.Sprintf(" %s ", v)))
			require.Equal(t, ErrSQLDetected, StringIs(fmt.Sprintf("%s ", strings.ToUpper(v))))
		}
		require.Equal(t, ErrCharsDetected, StringIs(" < "))
		require.Equal(t, ErrCharsDetected, StringIs(" > "))
		require.Equal(t, ErrHTMLDetected, StringIs("&gt;"))
		require.Equal(t, ErrHTMLDetected, StringIs("&lt;"))
		require.Equal(t, ErrHTMLDetected, StringIs("window.onload"))
		require.Equal(t, ErrWSDetected, StringIs(`
                                      multi
                                      line
                                     `))
		require.Equal(t, ErrWSDetected, StringIs("\thello\t"))
	})

	t.Run("Empty", func(t *testing_.T) {
		t.Parallel()
		_, err := NewVarChar("")
		require.Error(t, err)
	})

	t.Run("JSON", func(t *testing_.T) {
		t.Parallel()
		type T struct {
			S VarChar `json:"s"`
		}
		c := T{S: TrustedVarChar("hello")}
		bs, err := json.Marshal(c)
		require.NoError(t, err)
		require.Equal(t, `{"s":"hello"}`, string(bs))
		out := &T{}
		err = json.Unmarshal(bs, out)
		require.NoError(t, err)
		require.Error(t, json.Unmarshal([]byte(`{"s":""}`), &T{}))
	})
}
