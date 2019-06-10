package tlv

import (
	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v2"
)

// Decode YAML into generic TLV structure
func Decode(str string) (Elements, error) {
	data := yaml.MapSlice{}
	if err := yaml.Unmarshal([]byte(str), &data); err != nil {
		return nil, errors.WithStack(err)
	}

	out := Elements{}
	err := decodeYaml(data, &out)
	return out, err
}

func decodeYaml(data yaml.MapSlice, out *Elements) error {
	for _, v := range data {
		//
		// Type
		// TODO Support named keys
		//
		t := -1
		switch a := v.Key.(type) {
		case int:
			t = a
		default:
			return errors.WithStack(errUnsupportedKeyType)
		}

		//
		// Value
		//
		switch b := v.Value.(type) {
		case yaml.MapSlice:
			s := Elements{}
			if err := decodeYaml(b, &s); err != nil {
				return errors.WithStack(err)
			}
			*out = append(*out, Element{t, nil, s})

		case []interface{}:
			if len(b) == 0 {
				return errors.WithStack(errUnsupportedValueType)
			}

			// The array @b should be homogeneous
			switch b[0].(type) {
			case yaml.MapSlice:
				s := Elements{}
				for _, d := range b {
					f, ok := d.(yaml.MapSlice)
					if !ok {
						return errors.WithStack(errUnsupportedValueType)
					}
					if err := decodeYaml(f, &s); err != nil {
						return errors.WithStack(err)
					}
				}
				*out = append(*out, Element{t, nil, s})

			case int:
				g := T8L16{}
				for _, d := range b {
					f, ok := d.(int)
					if !ok {
						return errors.WithStack(errUnsupportedValueType)
					}
					g = append(g, byte(f))
				}
				*out = append(*out, Element{t, T8L16(g), nil})

			default:
				return errors.WithStack(errUnsupportedValueType)
			}

		case string:
			*out = append(*out, Element{t, T8L16(b), nil})
		case []byte:
			*out = append(*out, Element{t, T8L16(b), nil})

		default:
			return errors.WithStack(errUnsupportedValueType)
		}
	}

	return nil
}
