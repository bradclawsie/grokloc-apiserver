package security

import (
	"errors"

	"github.com/google/uuid"
)

// KeyMap is the data structure used to hold key ids
// (as UUIDs) -> key []byte.
type KeyMap map[uuid.UUID][]byte

var (
	ErrKeyNotFound        = errors.New("key not set in key map")
	ErrCurrentKeyNotFound = errors.New("current key not set in key map")
)

// VersionKey maps key ids (as UUIDs) to key []byte and
// knows the current key id -> key []byte mapping.
type VersionKey struct {
	keyMap  KeyMap
	current uuid.UUID
}

// NewVersionKey creates a new VersionKey assuming current
// is a valid key in `keyMap`.
func NewVersionKey(keyMap KeyMap, current uuid.UUID) (*VersionKey, error) {
	if _, ok := keyMap[current]; !ok {
		return nil, ErrCurrentKeyNotFound
	}
	v := VersionKey{}
	v.keyMap = make(KeyMap)
	for id, key := range keyMap {
		c := make([]byte, len(key))
		copy(c, key)
		v.keyMap[id] = c
	}
	v.current = current
	return &v, nil
}

// Get looks up a key identified by id in the keyMap.
func (v *VersionKey) Get(id uuid.UUID) ([]byte, error) {
	k, ok := v.keyMap[id]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return k, nil
}

// GetCurrent looks up the current key in the keyMap.
func (v *VersionKey) GetCurrent() (uuid.UUID, []byte, error) {
	k, err := v.Get(v.current)
	if err != nil {
		// somehow the keyMap was not properly created, current should be present
		var u uuid.UUID
		return u, nil, ErrCurrentKeyNotFound
	}
	return v.current, k, nil
}
