package tlv

import (
	"fmt"
	"reflect"
)

// Unmarshal TLV data to struct.
// The struct fields must be public and has tags.
// The fields may be pointer to value. In this case it will be allocated,
// if input data has such element.
// Explicit map is not needed, as it taken from fields struct tags.
// The struct tag has form `tlv:"1.2.3.4"` but only last octet has meaning.
// Leading octects are for documenting purpose and may even be not a digit.
func ExampleUnmarshal() {
	type Struct struct {
		A uint16  `tlv:"1.1"`
		B string  `tlv:"1.2"`
		C *string `tlv:"1.3"`
		D *uint16 `tlv:"1.4"`
	}

	type Out struct {
		Out1 Struct `tlv:"1"`
	}

	data := T8L16{
		1, 0, 17, // <- this goes to v.Out1 - TLV type 1

		1, 0, 2, 0xDE, 0xAD, // <- this goes to v.Out1.A - TLV type 1.1
		2, 0, 4, 'a', 'b', 'c', 'd', // <- this goes to v.Out1.B - TLV type 1.2
		// The v.Out1.C stays nil as there is no element for TLV type 1.3
		4, 0, 2, 0x11, 0x22, // <- this goes to v.Out1.D, which will be allocated - TLV type 1.4
	}

	var v Out
	left, err := Unmarshal(data, &v)

	fmt.Printf("left %v\n", left)
	fmt.Printf("err %v\n", err)
	if v.Out1.D != nil { // The v.Out1.D must be allocated by Unmarshal
		fmt.Printf("value 0x%X %#v %v 0x%X\n", v.Out1.A, v.Out1.B, v.Out1.C, *v.Out1.D)
	}
	// Output:
	// left []
	// err <nil>
	// value 0xDEAD "abcd" <nil> 0x1122
}

// Unmarshal TLV data to slice of structs
func ExampleUnmarshal_sliceOfStructs() {
	type Struct struct {
		A uint16  `tlv:"1.1"`
		B string  `tlv:"1.2"`
		C *string `tlv:"1.3"`
		D *uint16 `tlv:"1.4"`
	}

	type Out struct {
		Out1 Struct `tlv:"1"`
	}

	data := T8L16{
		// Next is first element in v
		1, 0, 17, // <- this goes to v.Out1 - TLV type 1

		1, 0, 2, 0xDE, 0xAD, // <- this goes to v.Out.A - TLV type 1.1
		2, 0, 4, 'a', 'b', 'c', 'd', // <- this goes to v.Out.B - TLV type 1.2
		4, 0, 2, 0x11, 0x22, // <- this goes to v.Out.D, which will be allocated - TLV type 1.4

		// The v.Out1.C stays nil as there is no element for TLV type 1.3

		// Next is second element in v
		1, 0, 17, // <- this goes to v.Out1 - TLV type 1

		1, 0, 2, 0xFA, 0xFA, // <- this goes to v.Out.A - TLV type 1.1
		2, 0, 4, 't', 'r', 'e', 'e', // <- this goes to v.Out.B - TLV type 1.2
		3, 0, 2, 'O', 'K', // <- this goes to v.Out.C, which will be allocated - TLV type 1.3
		// The v.Out1.D stays nil as there is no element for TLV type 1.4
	}

	var v []Out
	left, err := Unmarshal(data, &v)

	fmt.Printf("left %v\n", left)
	fmt.Printf("err %v\n", err)
	fmt.Printf("len is %d\n", len(v))
	if len(v) == 2 {
		fmt.Printf("value[0] 0x%X %#v %v 0x%X\n", v[0].Out1.A, v[0].Out1.B, v[0].Out1.C, *v[0].Out1.D)
		fmt.Printf("value[1] 0x%X %#v %#v %v\n", v[1].Out1.A, v[1].Out1.B, *v[1].Out1.C, v[1].Out1.D)
	}
	// Output:
	// left []
	// err <nil>
	// len is 2
	// value[0] 0xDEAD "abcd" <nil> 0x1122
	// value[1] 0xFAFA "tree" "OK" <nil>
}

// Unmarshal TLV data to empty interface.
// Such use case requires mandatory hinting on map between TLV types and Go values.
func ExampleUnmarshal_emptyInterface() {
	type Struct1 struct { //`tlv:"1"`
		Value string `tlv:"1.1"`
	}
	type Struct2 struct { //`tlv:"2"`
		Value string `tlv:"2.1"`
	}

	m := Map{
		1: {T: reflect.TypeOf(Struct1{})},
		2: {T: reflect.TypeOf(Struct2{})},
	}

	data := T8L16{2, 0, 18, 1, 0, 15, 't', 'h', 'i', 's', ' ', 'i', 's', ' ', 'S', 't', 'r', 'u', 'c', 't', '2'}
	var v interface{}

	// Unmarshal detect the TLV type and allocate for it proper structure to v.
	// In this case the TLV type 2 maps to Struct2.
	// The Struct2's fields unmarshaled base on struct tags.
	left, err := Unmarshal(data, &v, m)

	fmt.Printf("left %v\n", left)
	fmt.Printf("err %v\n", err)
	fmt.Printf("value type is %T\n", v)
	fmt.Printf("value is %v\n", v)

	// Output:
	// left []
	// err <nil>
	// value type is tlv.Struct2
	// value is {this is Struct2}
}

// Unmarshal TLV data to slice of empty interfaces
func ExampleUnmarshal_sliceOfEmptyInterface() {
	type Struct1 struct { //`tlv:"1"`
		Value string `tlv:"1.1"`
	}
	type Struct2 struct { //`tlv:"2"`
		Value string `tlv:"2.1"`
	}

	m := Map{
		1: {T: reflect.TypeOf(Struct1{})},
		2: {T: reflect.TypeOf(Struct2{})},
	}

	data := T8L16{
		1, 0, 18, 1, 0, 15, 't', 'h', 'i', 's', ' ', 'i', 's', ' ', 'S', 't', 'r', 'u', 'c', 't', '1',
		2, 0, 18, 1, 0, 15, 't', 'h', 'i', 's', ' ', 'i', 's', ' ', 'S', 't', 'r', 'u', 'c', 't', '2',
	}
	var v []interface{}

	// Unmarshal detect the TLV type and allocate for it proper structure.
	left, err := Unmarshal(data, &v, m)

	fmt.Printf("left %v\n", left)
	fmt.Printf("err %v\n", err)
	fmt.Printf("len is %v\n", len(v))
	if len(v) == 2 {
		fmt.Printf("value[0] type is %T\n", v[0])
		fmt.Printf("value[0] is %v\n", v[0])
		fmt.Printf("value[1] type is %T\n", v[1])
		fmt.Printf("value[1] is %v\n", v[1])
	}
	// Output:
	// left []
	// err <nil>
	// len is 2
	// value[0] type is tlv.Struct1
	// value[0] is {this is Struct1}
	// value[1] type is tlv.Struct2
	// value[1] is {this is Struct2}
}

type Struct struct { //`tlv:"x"`
	Type    byte
	Order   []byte
	Empty   []byte
	Value   uint16        `tlv:"x.1"`
	Unknown []interface{} `tlv:"others"`
}

func (s *Struct) SetTLVType(t byte) {
	s.Type = t
}
func (s *Struct) NotifyTLVType(t byte, _ string) {
	s.Order = append(s.Order, t)
}
func (s *Struct) EmptyTLVType(t byte, _ string) {
	s.Empty = append(s.Empty, t)
}

// Unmarshal TLV data to empty interface with extra info on unmarshaled data.
func ExampleUnmarshal_emptyInterfaceWithUnmarshaler() {
	// The Struct has filed "Type".
	// When Unmarshal instantiate it, it going to call on it SetTLVType.
	// So the Struct method can store the value in Type, and later it may be reused
	// to find which TLV Type the struct was allocated for.

	// Field "Order" via NotifyTLVType keeps order of elements.

	// Field "Empty" via EmptyTLVType keeps list of empty elements.

	// Filed "Unknown" will collect all others TLV Type yet unknown.
	/*
		type Struct struct { //`tlv:"x"`
			Type    byte
			Order   []byte
			Empty   []byte
			Value   uint16        `tlv:"x.1"`
			Unknown []interface{} `tlv:"others"`
		}

		func (s *Struct) SetTLVType(t byte) {
			s.Type = t
		}
		func (s *Struct) NotifyTLVType(t byte, _ string) {
			s.Order = append(s.Order, t)
		}
		func (s *Struct) EmptyTLVType(t byte, _ string) {
			s.Empty = append(s.Empty, t)
		}
	*/

	m := Map{
		1: {T: reflect.TypeOf(Struct{})},
		2: {T: reflect.TypeOf(Struct{})},
	}

	data := T8L16{
		1, 0, 12, 1, 0, 2, 0x11, 0x22, 2, 0, 4, 5, 6, 7, 8,
		2, 0, 8, 4, 0, 0, 1, 0, 2, 0x78, 0x9A,
	}

	var v []interface{}

	left, err := Unmarshal(data, &v, m)

	fmt.Printf("left %v\n", left)
	fmt.Printf("err %v\n", err)
	fmt.Printf("len is %v\n", len(v))
	for index, value := range v {
		s, ok := value.(Struct)
		if !ok {
			continue
		}
		fmt.Printf("value[%d] %d 0x%04X %v %v %v\n", index, s.Type, s.Value, s.Unknown, s.Order, s.Empty)
	}
	// Output:
	// left []
	// err <nil>
	// len is 2
	// value[0] 1 0x1122 [[2 0 4 5 6 7 8]] [1 2] []
	// value[1] 2 0x789A [[4 0 0]] [4 1] [4]
}

// Unmarshal TLV data to basic type.
// Note for basic types the input data has only value. No T or L is expected.
func ExampleUnmarshal_basicType() {
	data := T8L16{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xFF, 0xFF}

	var v int64
	left, err := Unmarshal(data, &v)

	fmt.Printf("left %v\n", left)
	fmt.Printf("err %v\n", err)
	fmt.Printf("value 0x%08X\n", v)
	// Output:
	// left [255 255]
	// err <nil>
	// value 0x1122334455667788
}

// Unmarshal TLV data to slice of basic type.
func ExampleUnmarshal_sliceOfBasicType() {
	data := T8L16{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	var v []uint16
	left, err := Unmarshal(data, &v)

	fmt.Printf("left %v\n", left)
	fmt.Printf("err %v\n", err)
	fmt.Printf("len is %v\n", len(v))
	for index, value := range v {
		fmt.Printf("value[%d] 0x%04X\n", index, value)
	}
	// Output:
	// left []
	// err <nil>
	// len is 4
	// value[0] 0x1122
	// value[1] 0x3344
	// value[2] 0x5566
	// value[3] 0x7788
}
