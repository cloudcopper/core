package tlv

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/pkg/errors"
)

var spaces = 4

// Stringify generic TLV structure into YAML
func Stringify(data Elements) (string, error) {
	var buf bytes.Buffer
	err := stringify(data, &buf, 0)
	return buf.String(), err
}

func stringify(data Elements, buf *bytes.Buffer, level int) error {
	indent := fmt.Sprintf("%*s", spaces*level, "")
	if len(data) > 1 {
		indent += "- "
	}

	for _, rec := range data {
		switch {
		case rec.Sub != nil:
			buf.WriteString(indent)
			buf.WriteString(fmt.Sprintf("%d:", rec.T))
			buf.WriteString("\n")
			if err := stringify(rec.Sub, buf, level+1); err != nil {
				return errors.Wrap(err, "unable to stringify child value")
			}

		case len(rec.V) == 0:
			buf.WriteString(indent)
			buf.WriteString(fmt.Sprintf("%d: ", rec.T))
			buf.WriteString("null")
			buf.WriteString("\n")

		case rec.Sub == nil:
			buf.WriteString(indent)
			buf.WriteString(fmt.Sprintf("%d: ", rec.T))
			toBuf(rec.V, buf)
			buf.WriteString("\n")

		default:
			return errors.WithStack(errUnsupportedValueType)
		}
	}

	return nil
}

func toBuf(t T8L16, buf *bytes.Buffer) {
	buf.WriteString("[")
	for i, b := range t {
		if i != 0 {
			buf.WriteString(",")
		}
		buf.WriteString(strconv.Itoa(int(b)))
	}
	buf.WriteString("]")
}
