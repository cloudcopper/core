package tlv

import (
	"reflect"

	"github.com/cloudcopper/core/encoding/binary"
	"github.com/pkg/errors"
)

// Unmarshal decode TLV data and stores the result in the Go value pointed by v.
// If v is not pointer to supported types, Unmarshal returns an error.
// Optional 3rd arg is map for TLV Types to Go types.
//
// Function returns unprocessed data and error.
//
// Supported input types: *struct, *[]struct, *interface{}, *[]interface{}, *T, *[]T
//
// In some cases you want to know more on unmarshaled data - i.e.
// order of elements, which elements had zero sized value, and TLV type
// for which the struct was allocated (i.e. many to one map relations).
// Then the structure should implemented interface Unmarshaler.
//
// Please see examples.
//
func Unmarshal(data T8L16, v interface{}, hint ...Map) ([]byte, error) {
	rv := reflect.Indirect(reflect.ValueOf(v))

	var m Map
	if len(hint) > 0 {
		m = hint[0]
	}

	var path []byte
	return unmarshal(data, rv, m, path)
}

// unmarshal process data to rv according to m until first error.
// The rv must not be a pointer. It must be dereference already.
func unmarshal(data T8L16, rv reflect.Value, m Map, path []byte) ([]byte, error) {
	// Check the preconditions
	if !rv.IsValid() {
		return data, ErrReflectValueIsInvalid
	}
	if rv.Kind() == reflect.Ptr {
		return data, ErrReflectValueMustNotBePtr
	}
	if !rv.CanSet() {
		return data, ErrReflectValueIsNotSettable
	}

	if rv.Kind() == reflect.Slice {
		return unmarshalSlice(data, rv, m, path)
	}

	return unmarshalValue(data, rv, m, path)
}

func unmarshalSlice(data T8L16, rv reflect.Value, m Map, path []byte) ([]byte, error) {
	t := rv.Type().Elem()
	if t.Kind() == reflect.Struct || t.Kind() == reflect.Interface {
		return unmarshalComplexSlice(data, rv, m, path)
	}

	if isByteSlice(rv) {
		// This is special case where rv is []byte
		// and there is no needs to process byte by byte
		// but whole slice could be just copied
		rv.SetBytes(data)
		return nil, nil
	}

	return unmarshalBasicSlice(data, rv, m, path)
}

func unmarshalBasicSlice(data T8L16, rv reflect.Value, m Map, path []byte) ([]byte, error) {
	for len(data) > 0 {
		v := reflect.Indirect(reflect.New(rv.Type().Elem()))

		rest, err := unmarshal(data, v, m, path)
		if err != nil {
			return data, errors.WithStack(err)
		}

		rv.Set(reflect.Append(rv, v))
		data = rest
	}

	return nil, nil
}

// The unmarshalComplexSlice reads out of data TLV elements
// one by one, unmarshal and append those to rv.
func unmarshalComplexSlice(data T8L16, rv reflect.Value, m Map, path []byte) ([]byte, error) {
	for len(data) > 0 {
		v := reflect.Indirect(reflect.New(rv.Type().Elem()))

		_, value, rest, err := data.Read()
		if err != nil {
			return data, errors.WithStack(err)
		}
		value = data[0 : 3+len(value)]

		left, err := unmarshal(value, v, m, path)
		if err != nil {
			return data, errors.WithStack(err)
		}
		if len(left) != 0 {
			return data, &UnprocessedDataError{left}
		}

		rv.Set(reflect.Append(rv, v))
		data = rest
	}

	return nil, nil
}

func unmarshalValue(data T8L16, rv reflect.Value, m Map, path []byte) ([]byte, error) {
	// The rv might be basic type.
	// In such case the m must be nil,
	// and we shall just unmarshal value.
	if isBasicType(rv) && m == nil {
		return unmarshalBasicType(data, rv, path)
	}
	if isString(rv) && m == nil {
		return unmarshalString(data, rv, path)
	}
	if isByteArray(rv) && m == nil {
		return unmarshalByteArray(data, rv, path)
	}

	if isInterface(rv) {
		return unmarshalInterface(data, rv, m, path)
	}
	if isStruct(rv) {
		return unmarshalStruct(data, rv, m, path)
	}

	return data, &WrongKindError{rv.Kind()}
}

func unmarshalInterface(data T8L16, rv reflect.Value, m Map, path []byte) ([]byte, error) {
	if m == nil {
		rv.Set(reflect.ValueOf(data))
		return nil, nil
	}

	// Read T and V
	t, v, rest, err := data.Read()
	if err != nil {
		return data, errors.WithStack(err)
	}

	// Find storage type for T
	r, ok := m[t]
	if !ok {
		r, ok = m[AllOthers]
		if !ok {
			return data, ErrTlvMapHasNoEntry
		}
		// In case of allOthers we shall not loose type info,
		// so prepend tl to v
		v = data[0 : len(v)+3]
	}

	pi := reflect.New(r.T)
	i := reflect.Indirect(pi)

	umi, _ := pi.Interface().(Unmarshaler)
	if umi != nil {
		umi.SetTLVType(t)
	}

	// When unmarshal to interface, the map shall not propagade
	left, err := unmarshal(v, i, nil, append(path, t))
	if err != nil {
		return data, errors.WithStack(err)
	}
	if len(left) != 0 {
		return data, &UnprocessedDataError{left}
	}

	rv.Set(i)
	return rest, nil
}

func unmarshalStruct(data T8L16, rv reflect.Value, m Map, path []byte) ([]byte, error) {
	// For non-basic types we shall have map.
	// If map m is not given, try to get it.
	if m == nil {
		var err error
		if m, err = getTlvMap(rv.Type()); err != nil {
			return data, errors.WithStack(err)
		}
		if m == nil {
			return data, ErrNoTlvMap
		}
	}

	// Try to obtain Unmarshaler interface
	umi, _ := rv.Addr().Interface().(Unmarshaler)

	// Process all data
	for len(data) > 0 {
		// Read T and V
		t, v, rest, err := data.Read()
		if err != nil {
			return data, errors.WithStack(err)
		}
		l := len(v)

		// Find storage type for T
		r, ok := m[t]
		if !ok {
			r, ok = m[AllOthers]
			if !ok {
				return data, ErrTlvMapHasNoEntry
			}
			// In case of allOthers we shall not loose type info,
			// so prepend tl to v
			v = data[0 : 3+l]
		}

		f := rv.FieldByName(r.K)
		if !f.IsValid() {
			return data, &ReflectValueHasNoFieldError{rv, r.K}
		}
		if umi != nil {
			umi.NotifyTLVType(t, r.K)
		}

		// If the field is pointer to value then it must be allocated
		if f.Kind() == reflect.Ptr {
			if f.IsNil() {
				f.Set(reflect.New(r.T.Elem()))
			}
			f = f.Elem()
		}

		if l == 0 && umi != nil {
			umi.EmptyTLVType(t, r.K)
		}
		if len(v) != 0 {
			// When unmarshal struct's field, the map shall not propagade
			left, err := unmarshal(v, f, nil, append(path, t))
			if err != nil {
				return data, errors.WithStack(err)
			}
			if len(left) != 0 {
				return data, &UnprocessedDataError{left}
			}
		}

		// Process rest of data
		data = rest
	}

	return nil, nil
}

func unmarshalBasicType(data []byte, rv reflect.Value, path []byte) ([]byte, error) {
	s := int(rv.Type().Size())
	if len(data) < s {
		// There is not enough data so we shall prepend zeroes
		zeroes := []byte{0, 0, 0, 0, 0, 0, 0, 0}
		data = append(zeroes[0:s-len(data)], data...)
	}

	switch k := rv.Kind(); k {
	case reflect.Bool:
		rv.SetBool(data[0] != 0)
		return data[1:], nil

	case reflect.Int8:
		rv.SetInt(int64(data[0]))
		return data[1:], nil

	case reflect.Int16:
		rv.SetInt(int64(binary.NetworkByteOrder.Uint16(data)))
		return data[2:], nil

	case reflect.Int32:
		rv.SetInt(int64(binary.NetworkByteOrder.Uint32(data)))
		return data[4:], nil

	case reflect.Int64:
		rv.SetInt(int64(binary.NetworkByteOrder.Uint64(data)))
		return data[8:], nil

	case reflect.Uint8:
		rv.SetUint(uint64(data[0]))
		return data[1:], nil

	case reflect.Uint16:
		rv.SetUint(uint64(binary.NetworkByteOrder.Uint16(data)))
		return data[2:], nil

	case reflect.Uint32:
		rv.SetUint(uint64(binary.NetworkByteOrder.Uint32(data)))
		return data[4:], nil

	case reflect.Uint64:
		rv.SetUint(uint64(binary.NetworkByteOrder.Uint64(data)))
		return data[8:], nil

	default:
		return data, &WrongKindError{k}
	}
}

func unmarshalString(data []byte, rv reflect.Value, path []byte) ([]byte, error) {
	switch k := rv.Kind(); k {
	case reflect.String:
		rv.SetString(string(data))
		return nil, nil

	default:
		return nil, &WrongKindError{k}
	}
}

func unmarshalByteArray(data []byte, rv reflect.Value, path []byte) ([]byte, error) {
	switch k := rv.Kind(); k {
	case reflect.Array:
		reflect.Copy(rv, reflect.ValueOf(data))
		return nil, nil

	default:
		return nil, &WrongKindError{k}
	}
}
