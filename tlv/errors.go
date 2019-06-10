package tlv

import "errors"

var errUnsupportedOutputType = errors.New("unsupported output type")
var errUnsupportedInputType = errors.New("unsupported input type")
var errUnsupportedKeyType = errors.New("unsupported key type")
var errUnsupportedValueType = errors.New("unsupported value type")
var errTlvUnmarshalNotEnoughData = errors.New("not enough data to unmarshal TLV")
