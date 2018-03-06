package tlv

import (
	"errors"
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

// ErrEmptyStructTag is the error when empty struct tag detected during Map generation.
var ErrEmptyStructTag = errors.New("empty struct tag")

// ErrReflectValueIsInvalid is the error when reflect.Value is not valid
var ErrReflectValueIsInvalid = errors.New("reflect value is invalid")

// ErrReflectValueMustNotBePtr is the error when reflect.Value must no be a pointer
var ErrReflectValueMustNotBePtr = errors.New("reflect value must not be ptr")

// ErrReflectValueIsNotSettable is the error when reflect.Value is not settable
var ErrReflectValueIsNotSettable = errors.New("reflect value is not settable")

// ErrNoTlvMap is the error when there is no TLV Map for TLV Type
var ErrNoTlvMap = errors.New("no tlv map")

// ErrTlvMapHasNoEntry is the error when the TLV Map has no entry for TLV Type
var ErrTlvMapHasNoEntry = errors.New("tlv map has no entry")
