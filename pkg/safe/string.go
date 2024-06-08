// Package safe provides types and methods for safe stored data.
package safe

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrSQLDetected means sql was found.
var ErrSQLDetected = errors.New("string is unsafe due to detected sql")

// ErrHTMLDetected means html was found.
var ErrHTMLDetected = errors.New("string is unsafe due to detected html")

// ErrWSDetected means disallowed whitespace was found.
var ErrWSDetected = errors.New("string is unsafe due to detected whitespace")

// ErrCharsDetected means disallowed chars were found.
var ErrCharsDetected = errors.New("string is unsafe due to prohibited chars")

// ErrStringLength means the string is zero-len or exceeds limit.
var ErrStringLength = errors.New("string is either zero-len or exceeds limit")

const MaxStringLength = 8192

// StringIs looks for disallowed patterns and returns an appropriate error.
func StringIs(s string) error {
	if len(strings.TrimSpace(s)) == 0 || len(s) > MaxStringLength {
		return ErrStringLength
	}

	sqlRE := regexp.MustCompile(`(?i)(?:insert\s|update\s|upsert\s|drop\s|create\s)\s`)
	if sqlRE.MatchString(s) {
		return ErrSQLDetected
	}

	htmlRE := regexp.MustCompile(`(?i)(?:\&gt\;|\&lt\;|window\.)`)
	if htmlRE.MatchString(s) {
		return ErrHTMLDetected
	}

	wsRE := regexp.MustCompile(`[\n\t\r]`)
	if wsRE.MatchString(s) {
		return ErrWSDetected
	}

	if strings.ContainsAny(s, "'\"`<>") {
		return ErrCharsDetected
	}

	return nil
}

// VarChar is a stringy type intended for sanity storage.
type VarChar struct {
	s string
}

// NewVarChar makes sure a string is safe for db storage.
func NewVarChar(raw string) (*VarChar, error) {
	err := StringIs(raw)
	if err != nil {
		return nil, err
	}
	return &VarChar{s: raw}, nil
}

// TrustedVarChar assumes you have already validated the input string.
func TrustedVarChar(trusted string) VarChar {
	return VarChar{s: trusted}
}

func (v VarChar) String() string {
	return v.s
}

func (v VarChar) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, v.String())), nil
}

func (v *VarChar) UnmarshalJSON(bs []byte) error {
	stripped := strings.TrimRight(strings.TrimLeft(string(bs), `"`), `"`)
	vOk, err := NewVarChar(string(stripped))
	if err != nil {
		return err
	}
	*v = *vOk
	return nil
}

func (v *VarChar) Scan(src interface{}) error {
	switch src := src.(type) {
	case nil:
		return nil

	case string:
		v_, err := NewVarChar(src)
		if err != nil {
			return err
		}
		*v = *v_

	case []byte:
		v_, err := NewVarChar(string(src))
		if err != nil {
			return err
		}
		*v = *v_

	default:
		return fmt.Errorf("scan %v into VarChar", src)
	}

	return nil
}

func (v VarChar) Value() (driver.Value, error) {
	return v.String(), nil
}

func (v VarChar) IsEmpty() bool {
	return len(v.s) == 0
}

// Password is a stringy type intended for sanity storage.
type Password struct {
	s string
}

// NewPassword makes sure a string is suitable as a password.
// Since validation is delegated to a kdf verification function,
// this is just a length check.
func NewPassword(raw string) (*Password, error) {
	if len(strings.TrimSpace(raw)) == 0 || len(raw) > MaxStringLength {
		return nil, ErrStringLength
	}
	return &Password{s: raw}, nil
}

// TrustedPassword assumes you have already validated the input string.
func TrustedPassword(trusted string) Password {
	return Password{s: trusted}
}

func (p Password) String() string {
	return p.s
}

func (p Password) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, p.String())), nil
}

func (p *Password) UnmarshalJSON(bs []byte) error {
	stripped := strings.TrimRight(strings.TrimLeft(string(bs), `"`), `"`)
	pOk, err := NewPassword(string(stripped))
	if err != nil {
		return err
	}
	*p = *pOk
	return nil
}

func (p *Password) Scan(src interface{}) error {
	switch src := src.(type) {
	case nil:
		return nil

	case string:
		p_, err := NewPassword(src)
		if err != nil {
			return err
		}
		*p = *p_

	case []byte:
		p_, err := NewPassword(string(src))
		if err != nil {
			return err
		}
		*p = *p_

	default:
		return fmt.Errorf("scan %v into Password", src)
	}

	return nil
}

func (p Password) Value() (driver.Value, error) {
	return p.String(), nil
}

func (p Password) IsEmpty() bool {
	return len(p.s) == 0
}
