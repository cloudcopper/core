package tlv

// This file has small helpers function to work with package reflect.

import (
	"reflect"
)

func isStruct(rv reflect.Value) bool {
	if !rv.IsValid() {
		return false
	}
	if rv.Kind() != reflect.Struct {
		return false
	}
	return true
}

func isInterface(rv reflect.Value) bool {
	if !rv.IsValid() {
		return false
	}
	if rv.Kind() != reflect.Interface {
		return false
	}
	return true
}

func isBasicType(rv reflect.Value) bool {
	if !rv.IsValid() {
		return false
	}
	if rv.Kind() < reflect.Bool {
		return false
	}
	if rv.Kind() > reflect.Complex128 {
		return false
	}
	return true
}

func isString(rv reflect.Value) bool {
	if !rv.IsValid() {
		return false
	}
	if rv.Kind() != reflect.String {
		return false
	}
	return true
}

func isSlice(rv reflect.Value) bool {
	if !rv.IsValid() {
		return false
	}
	if rv.Kind() != reflect.Slice {
		return false
	}

	return true
}
func isSliceOf(rv reflect.Value, t reflect.Type) bool {
	if !isSlice(rv) {
		return false
	}
	if rv.Type().Elem() != t {
		return false
	}

	return true
}
func isByteSlice(rv reflect.Value) bool {
	t := reflect.TypeOf(byte(0))
	return isSliceOf(rv, t)
}
func isSliceOfInterfaces(rv reflect.Value) bool { // nolint:deadcode,megacheck
	t := reflect.TypeOf([]interface{}{}).Elem()
	return isSliceOf(rv, t)
}

func isArray(rv reflect.Value) bool {
	if !rv.IsValid() {
		return false
	}
	if rv.Kind() != reflect.Array {
		return false
	}

	return true
}
func isArrayOf(rv reflect.Value, t reflect.Type) bool {
	if !isArray(rv) {
		return false
	}
	if rv.Type().Elem() != t {
		return false
	}

	return true
}
func isByteArray(rv reflect.Value) bool {
	t := reflect.TypeOf(byte(0))
	return isArrayOf(rv, t)
}
