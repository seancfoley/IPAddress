package ipaddr

const (
	IPv6SegmentSeparator           = ':'
	IPv6ZoneSeparator              = '%'
	IPv6AlternativeZoneSeparator   = '\u00a7'
	IPv6BitsPerSegment             = 16
	IPv6BytesPerSegment            = 2
	IPv6SegmentCount               = 8
	IPv6MixedReplacedSegmentCount  = 2
	IPv6MixedOriginalSegmentCount  = 6
	IPv6ByteCount                  = 16
	IPv6BitCount                   = 128
	IPv6DefaultTextualRadix        = 16
	IPv6MaxValuePerSegment         = 0xffff
	IPv6ReverseDnsSuffix           = ".ip6.arpa"
	IPv6ReverseDnsSuffixDeprecated = ".ip6.int"

	IPv6UncSegmentSeparator = '-'
	IPv6UncZoneSeparator    = 's'
	IPv6UncRangeSeparator   = AlternativeRangeSeparator
	IPv6UncSuffix           = ".ipv6-literal.net"

	IPv6SegmentMaxChars    = 4
	IPv6SegmentBitsPerChar = 4
)

type Zone string

//
//
//
type IPv6Address struct {
	ipAddressInternal
}

func (addr IPv6Address) init() {
	if addr.hasNoDivisions() {
		div := NewIPv6Segment(0).ToAddressDivision()
		addr.section = AddressSection{AddressDivisionGrouping{
			divisions: []AddressDivision{div, div, div, div, div, div, div, div}}}
	}
}

func (addr IPv6Address) ToAddress() Address {
	addr.init()
	return addr.Address
}

func (addr IPv6Address) ToIPAddress() IPAddress {
	addr.init()
	return addr.IPAddress
}

func (addr IPv6Address) ToIPv6Address() IPv6Address {
	return addr
}
