package tlv

import (
	"io"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/cloudcopper/core/encoding/binary"
	"github.com/pkg/errors"
)

// T8L16 is the type for TLV (Type-Length-Value) raw data
// where Type is 1 octet (byte)
// and Length is 2 octets (uint16).
type T8L16 []byte

// Read return T, V, rest and optional error
func (data T8L16) Read() (byte, []byte, T8L16, error) {
	lenData := len(data)
	if lenData < 3 {
		return 0, nil, data, io.ErrShortBuffer
	}

	l := int(binary.NetworkByteOrder.Uint16(data[1:]))
	if l > (lenData - 3) { // there is not enough data in buffer
		return 0, nil, data, io.ErrShortBuffer
	}

	t := data[0]
	v := data[3:][:l]
	rest := data[3:][l:]

	return t, v, rest, nil
}

// Unmarshaler is the interface implemented by the type that can
// proactively partitipate unmarshaling.
// SetTLVType set the actual TLV type to Go value.
// NotifyTLVType notify order of properties in input TLV.
// EmptyTLVType notify on empty properties in input TLV.
type Unmarshaler interface {
	SetTLVType(byte)
	NotifyTLVType(byte, string)
	EmptyTLVType(byte, string)
}

// Map type keeps mapping between TLV types and Go types.
// The key is the TLV Type.
type Map map[byte]MapEntry

// MapEntry is the type of single entry in Map.
// The K is the property name. It is given to NotifyTLVType and
// may point to struct field for Unmarshal.
// The T is reflect.Type of target Go value.
// Note - when https://github.com/golang/go/issues/16869 got resolved -
// reflect.TypeOf going be optimized out during compilation.
type MapEntry struct {
	K string
	T reflect.Type
}

// AllOthers is the special Map key used by Unmarshal to catch all others TLV types.
const AllOthers = 0

// The getTlvMap returns cached Map of TLV Types to Go struct fields.
// The map is build out of struct using structr tags.
// The map is cached in cacheTlvMap.
func getTlvMap(t reflect.Type) (Map, error) {
	// Try to get the map out of cache
	if m, ok := cacheTlvMap.Load(t); ok {
		return m.(Map), nil
	}

	// Validate the requested type. Shall be struct
	if t.Kind() != reflect.Struct {
		return nil, &WrongKindError{t.Kind(), nil}
	}

	// Create map out of all fields of requested struct type
	m := make(Map)
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)

		// Parse tag "tlv"
		// It must have value "others" or type in canonical form - i.e. "50.19.1"
		// Only last digit is used.
		tag, ok := sf.Tag.Lookup("tlv")
		if !ok {
			continue
		}
		if tag == "" {
			return nil, ErrEmptyStructTag
		}

		var n byte
		if tag == "others" {
			n = AllOthers
		} else {
			as := strings.Split(tag, ".")
			s := as[len(as)-1]
			base := 0
			bitSize := 8
			i, err := strconv.ParseInt(s, base, bitSize)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			n = byte(i)
		}

		entry := MapEntry{sf.Name, sf.Type}
		m[n] = entry
	}

	cacheTlvMap.Store(t, m)
	return m, nil
}

var cacheTlvMap sync.Map // map[reflect.Value]TlvMap
