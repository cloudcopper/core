package tlv

import (
	"os"

	"github.com/cloudcopper/core/encoding/binary"
	"github.com/pkg/errors"
)

// TODO Check bytes.Buffer - would it be nicer to use here? consider less SLOC
var chunkSize = os.Getpagesize()

// Marshal encode generic TLV structure into TLV data
func Marshal(in Elements) (T8L16, error) {
	strict := false
	buf := make([]byte, chunkSize)
	pos := chunkSize
	// The resize function increases buf to fit at least r more bytes
	resize := func(r int) {
		r /= chunkSize
		r++
		r *= chunkSize

		l := cap(buf) + r
		b := make([]byte, l, l)

		copy(b[pos+r:], buf[pos:])
		pos += r
		buf = b
	}

	size := 0
	var f func(Elements) error
	f = func(in Elements) error {
		for i := len(in) - 1; i >= 0; i-- {
			el := &(in)[i]

			if !strict {
				if el.T < 0 || el.T > 255 {
					continue
				}
			}

			switch {
			case el.Sub != nil:
				bk := size
				size = 0
				if err := f(el.Sub); err != nil {
					return errors.WithStack(err)
				}
				if pos < 3 {
					resize(3)
				}
				// Length
				pos -= 2
				binary.NetworkByteOrder.PutUint16(buf[pos:], uint16(size))
				// Type
				pos--
				buf[pos] = byte(el.T)

				size += bk + 3

			case el.Sub == nil:
				l := len(el.V)
				r := l + 3 /*T 1byte, L 2bytes, V xbytes*/
				for pos <= r {
					resize(r)
				}

				// Value
				pos -= l
				copy(buf[pos:], el.V)
				// Length
				pos -= 2
				binary.NetworkByteOrder.PutUint16(buf[pos:], uint16(l))
				// Type
				pos--
				buf[pos] = byte(el.T)

				size += r
			}
		}

		return nil
	}
	if err := f(in); err != nil {
		return nil, errors.WithStack(err)
	}

	return buf[pos:], nil
}
