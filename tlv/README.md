Package tlv
===========

Package tlv implements marshal/unmarshal between TLV (Type-Length-Value), YAML and generic TLV structure.
It handles only T8L16 data where Type is 1 octet (byte)
and Length is 2 octets (uint16) (i.e. R-PHY Control Protocol(RCP)).

It does not support others formats (i.e. T8L8 as in DOCSIS MULPI).

TODO
====

* license
* consts instead of 1, 2 and 3(which actually 1+2)
* slice vs bytes.Buffer
