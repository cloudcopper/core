Package tlv
===========

Package tlv implements decoding of TLV (Type-Length-Value) to Go values.
The mapping between T8L16 and Go values is described in the documentation
for the Unmarshal function.
It handles only T8L16 input data where Type is 1 octet (byte)
and Length is 2 octets (uint16) (i.e. R-PHY Control Protocol(RCP)).

It does not support others formats (i.e. T8L8 as in DOCSIS MULPI) at the moment.

Marshal function is out of scope for this package.

See full doc at https://godoc.org/github.com/cloudcopper/core/encoding/tlv
