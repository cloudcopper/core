package tlv

import (
	"fmt"
	"reflect"
)

// WrongKindError is the error returned when wrong reflect.Kind being detected.
type WrongKindError struct {
	kind reflect.Kind
}

func (e *WrongKindError) Error() string {
	return fmt.Sprintf("wrong kind %v", e.kind)
}

// UnprocessedDataError is the error returned when there is unprocessed data
type UnprocessedDataError struct {
	data []byte
}

func (e *UnprocessedDataError) Error() string {
	return fmt.Sprintf("unprocessed data %v", e)
}

// ReflectValueHasNoFieldError is the error returned when the reflect.Value has no field
type ReflectValueHasNoFieldError struct {
	rv    reflect.Value
	field string
}

func (e *ReflectValueHasNoFieldError) Error() string {
	return fmt.Sprintf("reflect value of type %v has no filed %v", e.rv.Type().Name(), e.field)
}

// Error type is a string to allow const errors within this package
type Error string

func (e Error) Error() string { return string(e) }

// ErrEmptyStructTag is the error when empty struct tag detected during Map generation.
const ErrEmptyStructTag = Error("empty struct tag")

// ErrReflectValueIsInvalid is the error when reflect.Value is not valid
const ErrReflectValueIsInvalid = Error("reflect value is invalid")

// ErrReflectValueMustNotBePtr is the error when reflect.Value must no be a pointer
const ErrReflectValueMustNotBePtr = Error("reflect value must not be ptr")

// ErrReflectValueIsNotSettable is the error when reflect.Value is not settable
const ErrReflectValueIsNotSettable = Error("reflect value is not settable")

// ErrNoTlvMap is the error when there is no TLV Map for TLV Type
const ErrNoTlvMap = Error("no tlv map")

// ErrTlvMapHasNoEntry is the error when the TLV Map has no entry for TLV Type
const ErrTlvMapHasNoEntry = Error("tlv map has no entry")
