package tlv

import (
	"github.com/cloudcopper/core/encoding/binary"
	"github.com/pkg/errors"
)

// Unmarshal decode TLV data into generic TLV structure
func Unmarshal(data interface{}, out *Elements) error {
	switch in := data.(type) {
	case T8L16:
		return UnmarshalT8L16(in, out)
	}
	return errors.WithStack(errUnsupportedInputType)
}

// UnmarshalT8L16 decode TLV data into generic TLV structure
func UnmarshalT8L16(data T8L16, out *Elements) error {
	for len(data) > 0 {
		if len(data) < 3 {
			return errors.WithStack(errTlvUnmarshalNotEnoughData)
		}

		t := int(data[0])
		l := int(binary.NetworkByteOrder.Uint16(data[1:]))
		var v T8L16
		var sub Elements

		if len(data) < 3+l {
			return errors.WithStack(errTlvUnmarshalNotEnoughData)
		}

		if l == 0 {
			v = nil
		} else {
			v = T8L16(data[3 : 3+l])
			sub = Elements{}
			if err := UnmarshalT8L16(v, &sub); err != nil {
				sub = nil
			} else {
				v = nil
			}
		}

		*out = append(*out, Element{t, v, sub})

		// Shift ...
		data = data[3+l:]
	}

	return nil
}
