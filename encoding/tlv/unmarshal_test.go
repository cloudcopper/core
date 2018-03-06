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

func TestUnmarshalToInterface(t *testing.T) {
	t.SkipNow()
}

func TestUnmarshalToInterfaceWithHint(t *testing.T) {
	t.SkipNow()
}
