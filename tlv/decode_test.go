package tlv

import (
	"net"
	"strconv"
	"testing"

	"github.com/cloudcopper/core/encoding/tlv"
	"github.com/stretchr/testify/assert"
)

func TestDecode1(t *testing.T) {
	assert := assert.New(t)

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
	msg, err := Decode(yaml)
	assert.NoError(err)

	str, err := Stringify(msg)
	assert.NoError(err)
	expStr := `9:
    - 10: [0,1]
    - 11: [7]
    - 60:
        - 2: [17,34,51,68,85,102]
        - 3: [47,208,1,0,0,0,0,0,0,0,0,0,0,0,18,52]
        - 4: [0]
        - 5: [103,111,45,99,99,97,112]
        - 6: [17,139]
        - 7: [2]
        - 8: [0]
        - 10: [0,16]
        - 201: [172,30,20,10]
        - 202: null
`
	assert.Equal(expStr, str)

	t8l16, err := Marshal(msg)
	assert.NoError(err)

	expBin := tlv.T8L16(tlv.T8L16{0x9, 0x0, 0x52, 0xa, 0x0, 0x2, 0x0, 0x1, 0xb, 0x0, 0x1, 0x7, 0x3c, 0x0, 0x46, 0x2, 0x0, 0x6, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x3, 0x0, 0x10, 0x2f, 0xd0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x12, 0x34, 0x4, 0x0, 0x1, 0x0, 0x5, 0x0, 0x7, 0x67, 0x6f, 0x2d, 0x63, 0x63, 0x61, 0x70, 0x6, 0x0, 0x2, 0x11, 0x8b, 0x7, 0x0, 0x1, 0x2, 0x8, 0x0, 0x1, 0x0, 0xa, 0x0, 0x2, 0x0, 0x10, 0xc9, 0x0, 0x4, 0xac, 0x1e, 0x14, 0xa, 0xca, 0x0, 0x0})
	assert.Equal(expBin, t8l16)
}

// TestDecodeAssumption tests assumptions used in tlv.Decode
// Those are - the parse methods are not truncating spaces,
// and failing, if those exists
func TestDecodeAssumption(t *testing.T) {
	assert := assert.New(t)
	var err error

	//
	var mac net.HardwareAddr
	mac, err = net.ParseMAC("0011.2233.4455")
	assert.NoError(err)
	assert.True(mac != nil)
	mac, err = net.ParseMAC("00:11:22:33:44:55")
	assert.NoError(err)
	assert.True(mac != nil)
	mac, err = net.ParseMAC("00:11:22:33:44:55 ")
	assert.Error(err)
	assert.True(mac == nil)
	mac, err = net.ParseMAC(" 00:11:22:33:44:55")
	assert.Error(err)
	assert.True(mac == nil)

	//
	var ip net.IP
	ip = net.ParseIP("2fd0:1:2:3::100")
	assert.True(!ip.IsUnspecified())
	assert.True(ip != nil)
	ip = net.ParseIP("2fd0:1:2:3::10 ")
	assert.True(ip == nil)
	ip = net.ParseIP(" fd0:1:2:3::100")
	assert.True(ip == nil)
	ip = net.ParseIP("173.100.10.33")
	assert.True(!ip.IsUnspecified())
	assert.True(ip != nil)
	ip = net.ParseIP("173.100.10.3 ")
	assert.True(ip == nil)
	ip = net.ParseIP(" 73.100.10.33")
	assert.True(ip == nil)

	//
	var i uint64
	i, err = strconv.ParseUint("1100", 0, 64)
	assert.NoError(err)
	assert.True(i == 1100)
	i, err = strconv.ParseUint("0xDEAD", 0, 64)
	assert.NoError(err)
	assert.True(i == 0xDEAD)
	i, err = strconv.ParseUint(" 100", 0, 64)
	assert.Error(err)
	i, err = strconv.ParseUint("110 ", 0, 64)
	assert.Error(err)
	i, err = strconv.ParseUint("-12", 0, 8)
	assert.Error(err)
	i, err = strconv.ParseUint("256", 0, 8)
	assert.Error(err)

	//
	var a []byte
	a, err = parseSliceOfBytes("")
	assert.Error(err)
	assert.True(a == nil)
	a, err = parseSliceOfBytes("[]")
	assert.NoError(err)
	assert.Equal([]byte{}, a)
	a, err = parseSliceOfBytes("[1,2,3,4,5]")
	assert.NoError(err)
	assert.Equal([]byte{1, 2, 3, 4, 5}, a)
	a, err = parseSliceOfBytes(" []")
	assert.Error(err)
	a, err = parseSliceOfBytes("[] ")
	assert.Error(err)
	a, err = parseSliceOfBytes(" [] ")
	assert.Error(err)
	a, err = parseSliceOfBytes("[256]")
	assert.Error(err)

	//
	var u uint16
	u, err = parseUint16("uint16(1234)")
	assert.NoError(err)
	assert.Equal(uint16(1234), u)
	u, err = parseUint16(" uint16(1234)")
	assert.Error(err)
	u, err = parseUint16("uint16(1234) ")
	assert.Error(err)
	u, err = parseUint16(" uint16(1234) ")
	assert.Error(err)
	u, err = parseUint16("uint16(0x1234)")
	assert.NoError(err)
	assert.Equal(uint16(0x1234), u)
}
