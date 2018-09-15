package tlv

import (
	"bytes"
	"net"
	"reflect"
	"testing"

	"github.com/cloudcopper/core/encoding/binary"
	"github.com/stretchr/testify/assert"
)

func TestLowUnmarshalValue(t *testing.T) {
	assert := assert.New(t)

	cases := []interface{}{
		bool(true),
		bool(false),
		byte(1),
		uint16(2),
		uint32(4),
		uint64(8),
		int16(16),
		int32(32),
		int64(64),
		int16(-128),
		int32(-256),
		int64(-1024),
		string("text text text"),
		[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09, 0x0A},
		net.ParseIP("192.0.2.1"),
		net.ParseIP("2001:db8::68"),
		net.HardwareAddr{0x00, 0x14, 0x22, 0x01, 0x23, 0x45},
	}

	// Run test cases
	for _, value := range cases {
		assert.NotNil(value)
		t.Logf("test %#v", value)

		t := reflect.TypeOf(value)
		assert.NotNil(t)

		buf := bytes.NewBuffer(nil)
		switch v := value.(type) {
		case string:
			if _, fatal := buf.WriteString(v); fatal != nil {
				assert.NoError(fatal)
			}
		default:
			if fatal := binary.Write(buf, binary.NetworkByteOrder, value); fatal != nil {
				assert.NoError(fatal)
			}
		}
		bytes := buf.Bytes()
		assert.NotEmpty(bytes)

		v := reflect.Indirect(reflect.New(t)) // The v is T
		assert.NotNil(v)

		rest, err := unmarshal(bytes, v, nil, []byte{})
		if assert.NoError(err) && assert.Len(rest, 0) {
			assert.Equal(value, v.Interface())
		}
	}
}

//
// Following is basic Unmarshal test
//
type TestStructRoot struct {
	TestStructWithOptionalFields *TestStructWithOptionalFields `tlv:"1"`
	ComplexTLV                   []interface{}                 `tlv:"others"`
}
type TestStructWithOptionalFields struct {
	A          int32         `tlv:"2"`
	B          *int32        `tlv:"3"`
	C          *int32        `tlv:"4"`
	ComplexTLV []interface{} `tlv:"others"`
}

func TestUnmarshalToStruct(t *testing.T) {
	assert := assert.New(t)

	a := int32(100)
	b := int32(200)
	data := T8L16{1, 0, 21, 2, 0, 4, 0, 0, 0, 100, 3, 0, 4, 0, 0, 0, 200, 5, 0, 4, 1, 2, 3, 4}

	out := TestStructRoot{}
	rest, err := Unmarshal(data, &out)

	assert.NoError(err)
	assert.Len(rest, 0)
	assert.Len(out.ComplexTLV, 0)

	if assert.NotNil(out.TestStructWithOptionalFields) {
		assert.Equal(a, out.TestStructWithOptionalFields.A)
		if assert.NotNil(out.TestStructWithOptionalFields.B) {
			assert.Equal(b, *(out.TestStructWithOptionalFields.B))
		}
		assert.Nil(out.TestStructWithOptionalFields.C)
		if assert.Len(out.TestStructWithOptionalFields.ComplexTLV, 1) {
			assert.IsType(T8L16{}, out.TestStructWithOptionalFields.ComplexTLV[0])
			assert.Equal(out.TestStructWithOptionalFields.ComplexTLV[0], T8L16{5, 0, 4, 1, 2, 3, 4})
		}
	}
}

func TestUnmarshalToSlice(t *testing.T) {
	t.SkipNow()
}

type TestStruct5 struct {
	//                  `tlv:"5"`
	Slice []TestStruct6 `tlv:"5.6"`
}
type TestStruct6 struct {
	//              `tlv:"5.6"`
	A byte          `tlv:"5.6.1"`
	B byte          `tlv:"5.6.2"`
	C []byte        `tlv:"5.6.3"`
	D *TestStruct6  `tlv:"5.6.4"`
	E []TestStruct6 `tlv:"5.6.5"`
}

func TestLowUnmarshalStuct1(t *testing.T) {
	assert := assert.New(t)
	r := &TestStruct6{}
	rv := reflect.Indirect(reflect.ValueOf(r))
	data := []byte{1, 0, 1, 1, 2, 0, 1, 2} // manually crafter data
	rest, err := unmarshalStruct(data, rv, nil, []byte{})
	assert.NoError(err)
	assert.Empty(rest)
	assert.EqualValues(1, r.A)
	assert.EqualValues(2, r.B)
}

func TestLowUnmarshalStuct2(t *testing.T) {
	assert := assert.New(t)
	r := &TestStruct6{}
	rv := reflect.Indirect(reflect.ValueOf(r))
	data := []byte{3, 0, 6, 1, 2, 3, 4, 5, 6} // manually crafter data
	rest, err := unmarshalStruct(data, rv, nil, []byte{})
	assert.NoError(err)
	assert.Empty(rest)
	assert.Equal([]byte{1, 2, 3, 4, 5, 6}, r.C)
}

func TestLowUnmarshalStuct3(t *testing.T) {
	assert := assert.New(t)
	r := &TestStruct6{}
	rv := reflect.Indirect(reflect.ValueOf(r))
	data := []byte{4, 0, 8, 1, 0, 1, 1, 2, 0, 1, 2} // manually crafter data
	rest, err := unmarshalStruct(data, rv, nil, []byte{})
	assert.NoError(err)
	assert.Empty(rest)
	if assert.NotNil(r.D) {
		assert.EqualValues(1, r.D.A)
		assert.EqualValues(2, r.D.B)
	}
}

func TestLowUnmarshalStuct4(t *testing.T) {
	assert := assert.New(t)
	r := &TestStruct6{}
	rv := reflect.Indirect(reflect.ValueOf(r))
	data := []byte{5, 0, 8, 1, 0, 1, 1, 2, 0, 1, 2, 5, 0, 8, 1, 0, 1, 3, 2, 0, 1, 4} // manually crafter data
	rest, err := unmarshalStruct(data, rv, nil, []byte{})
	assert.NoError(err)
	assert.Empty(rest)
	if assert.Len(r.E, 2) {
		assert.EqualValues(1, r.E[0].A)
		assert.EqualValues(2, r.E[0].B)
		assert.EqualValues(3, r.E[1].A)
		assert.EqualValues(4, r.E[1].B)
	}
}

// TestLowUnmarshalInterface similar to TestLowUnmarshalStruct,
// but result is interface and hint provided
func TestLowUnmarshalInterface(t *testing.T) {
	assert := assert.New(t)
	var r interface{}
	pr := &r
	rv := reflect.Indirect(reflect.ValueOf(pr))
	data := []byte{6, 0, 8, 1, 0, 1, 1, 2, 0, 1, 2} // manually crafter data
	hint := Map{
		byte(6): {T: reflect.TypeOf(TestStruct6{})},
	}
	rest, err := unmarshalInterface(data, rv, hint, []byte{})
	assert.NoError(err)
	assert.Empty(rest)
	if assert.IsType(TestStruct6{}, r) {
		r := r.(TestStruct6)
		assert.EqualValues(1, r.A)
		assert.EqualValues(2, r.B)
	}
}

func TestUnmarshalToInterface(t *testing.T) {
	t.SkipNow()
}

func TestUnmarshalToInterfaceWithHint(t *testing.T) {
	assert := assert.New(t)
	data := T8L16{5, 0, 11, 6, 0, 8, 1, 0, 1, 1, 2, 0, 1, 2}
	hint := Map{
		byte(5): {T: reflect.TypeOf(TestStruct5{})}, // `tlv:"5"`
	}
	var r interface{}
	rest, err := Unmarshal(data, &r, hint)
	assert.NoError(err)
	assert.Empty(rest)
	if assert.NotEmpty(r) {
		if assert.IsType(TestStruct5{}, r) {
			r := r.(TestStruct5)
			assert.Len(r.Slice, 1, "Slice must have one object")
			assert.EqualValues(1, r.Slice[0].A, "Property A must be 1")
			assert.EqualValues(2, r.Slice[0].B, "Property B must be 2")
		}
	}
}
