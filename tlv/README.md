Package tlv
===========

Package tlv implements marshal/unmarshal between TLV (Type-Length-Value), YAML and generic TLV structure.
It handles only T8L16 data where Type is 1 octet (byte)
and Length is 2 octets (uint16) (i.e. R-PHY Control Protocol(RCP)).

It does not support others formats (i.e. T8L8 as in DOCSIS MULPI).

Example
=======

```
func GetGcpAllocateWrite() ([]byte, err) {
	yaml := `# This is example of R-PHY GCP AllocateWrite message
Sequence(9):
    SequenceNumber(10): [0,1]
    Operation(11): [7]
    CcapCoreIdentification(60):
        - CoreId(2):        11:22:33:44:55:66 # MAC
        - CoreIpAddress(3): 2fd0:100::1234    # IPv6 address
        - IsPrincipal(4):   [0]
        - CoreName(5):      "go-ccap"
        - VendorId(6):      uint16(4491)
        - CoreMode(7):      [2]
        - InitialConfigurationComplete(8): false
        - CoreFunction(10): [0,16]
        # following is just unrealistic values for this test 
        - 201:              172.30.20.10 # IPv4
        - 202:              null
`
	msg, err := tlv.Decode(yaml)
    if err != nil {
        return nil, err
    }

	bin, err := Marshal(msg)
	return bin, err
}
```

TODO
====

* license
* consts instead of 1, 2 and 3(which actually 1+2)
* slice vs bytes.Buffer
