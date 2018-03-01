// Package binary aliasing binary.BigEndian as binary.NetworkByteOrder.
package binary

import "encoding/binary"

// NetworkByteOrder is alias to binary.BigEndian
var NetworkByteOrder = binary.BigEndian

// Write is alias to binary.Write
var Write = binary.Write

// Read is alias to binary.Read
var Read = binary.Read
