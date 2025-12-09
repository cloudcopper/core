package tlv

import "errors"

var errNoYamlDocumentNode = errors.New("no yaml document node found")
var errUnsupportedInputType = errors.New("unsupported input type")
var errUnsupportedKey = errors.New("unsupported key")
var errUnsupportedValue = errors.New("unsupported value")
var errUnsupportedValueType = errors.New("unsupported value type")
var errTlvUnmarshalNotEnoughData = errors.New("not enough data to unmarshal TLV")
var errCanNotParseSliceOfBytes = errors.New("can not parse slice of bytes")
var errStringTooShort = errors.New("string too short")
var errWrongFormat = errors.New("wrong format")
var errUnsupportedYamlNodeKind = errors.New("unsupported yaml node kind")
var errYamlMappingNodeWrongContentSize = errors.New("yaml node mapping has wrong content size")
var errNotAllYamlNodesProcessed = errors.New("not all yaml nodes processed")
