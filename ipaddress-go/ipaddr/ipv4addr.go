package ipaddr

const (
	IPv4SegmentSeparator    = '.'
	IPv4BitsPerSegment      = 8
	IPv4BytesPerSegment     = 1
	IPv4SegmentCount        = 4
	IPv4ByteCount           = 4
	IPv4BitCount            = 32
	IPv4DefaultTextualRadix = 10
	IPv4MaxValuePerSegment  = 0xff
	IPv4MaxValue            = 0xffffffff
	IPv4ReverseDnsSuffix    = ".in-addr.arpa"
	IPv4SegmentMaxChars     = 3
)

//
//
//
type IPv4Address struct {
	ipAddressInternal
}

func (addr IPv4Address) init() {
	if addr.hasNoDivisions() {
		div := NewIPv4Segment(0).ToAddressDivision()
		addr.section = AddressSection{AddressDivisionGrouping{
			divisions: []AddressDivision{div, div, div, div}}}
	}
}

func (addr IPv4Address) ToAddress() Address {
	addr.init()
	return addr.Address
}

func (addr IPv4Address) ToIPAddress() IPAddress {
	addr.init()
	return addr.IPAddress
}

func (addr IPv4Address) ToIPv4Address() IPv4Address {
	return addr
}
