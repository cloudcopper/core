package tlv

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

/*
As DataAndTime seen in RFC2579

A date-time specification.

field  octets  contents                  range
-----  ------  --------                  -----

	 1      1-2   year*                     0..65536
	 2       3    month                     1..12
	 3       4    day                       1..31
	 4       5    hour                      0..23
	 5       6    minutes                   0..59
	 6       7    seconds                   0..60
	              (use 60 for leap-second)
	 7       8    deci-seconds              0..9
	 8       9    direction from UTC        '+' / '-'
	 9      10    hours from UTC*           0..13
	10      11    minutes from UTC          0..59
*/
func TestTime8(t *testing.T) {
	assert := assert.New(t)

	var v time.Time
	rest, err := Unmarshal(T8L16{0x07, 0xE9, 11, 29, 8, 30, 22, 7}, &v)
	assert.NoError(err)
	assert.Empty(rest)

	assert.Equal(v.Year(), 2025)
	assert.Equal(v.Month(), time.Month(11))
	assert.Equal(v.Day(), 29)
	assert.Equal(v.Hour(), 8)
	assert.Equal(v.Minute(), 30)
	assert.Equal(v.Second(), 22)
	assert.Equal(v.Nanosecond(), 7*100_000_000)

	_, z := v.Zone()
	assert.Zero(z)
}

func TestTime11(t *testing.T) {
	assert := assert.New(t)

	var v time.Time
	rest, err := Unmarshal(T8L16{0x07, 0xE9, 11, 29, 8, 30, 22, 7, byte('-'), 3, 30}, &v)
	assert.NoError(err)
	assert.Empty(rest)

	assert.Equal(v.Year(), 2025)
	assert.Equal(v.Month(), time.Month(11))
	assert.Equal(v.Day(), 29)
	assert.Equal(v.Hour(), 8)
	assert.Equal(v.Minute(), 30)
	assert.Equal(v.Second(), 22)
	assert.Equal(v.Nanosecond(), 7*100_000_000)

	_, z := v.Zone()
	assert.Equal(z, -(3*3600 + 30*60))
}
