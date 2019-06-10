package tlv

import (
	"github.com/cloudcopper/core/encoding/tlv"
)

// T8L16 is a type for TLV format where Type is 1 octet (byte) and Length is 2 octets (uint16)
type T8L16 = tlv.T8L16

// Elements is generic TLV structure
type Elements []Element

// Element is single element of generic TLV structure.
// It shall have either value (V), or sub-elements (sub).
type Element struct {
	T int
	// Until https://github.com/golang/go/issues/19412 resolved,
	// we have to use either two field or interface{}
	V   T8L16
	Sub Elements
}
