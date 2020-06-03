package ipaddr

const (
	HexPrefix                  = "0x"
	OctalPrefix                = "0"
	RangeSeparator             = '-'
	AlternativeRangeSeparator  = '\u00bb'
	SegmentWildcard            = '*'
	AlternativeSegmentWildcard = '¿'
	SegmentSqlWildcard         = '%'
	SegmentSqlSingleWildcard   = '_'

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

	IPv6SegmentSeparator           = ':'
	IPv6ZoneSeparator              = '%'
	IPv6AlternativeZoneSeparator   = '\u00a7'
	IPv6BitsPerSegment             = 16
	IPv6BytesPerSegment            = 2
	IPv6SegmentCount               = 8
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
)

//
//
//
type Address struct {
	section AddressSection
	zone    string
}

func (addr Address) hasNoDivisions() bool {
	return addr.section.hasNoDivisions()
}

func (addr Address) ToIPAddress() IPAddress {
	if addr.section.matchesIPv4Address() || addr.section.matchesIPv6Address() {
		return IPAddress{addr}
	}
	return IPAddress{}
}

func (addr Address) ToIPv6Address() IPv6Address {
	return addr.ToIPAddress().ToIPv6Address()
}

func (addr Address) ToIPv4Address() IPv4Address {
	return addr.ToIPAddress().ToIPv4Address()
}

//
//
//
type IPAddress struct {
	Address
}

func (addr IPAddress) ToAddress() Address {
	return addr.Address
}

func (addr IPAddress) ToIPAddress() IPAddress {
	return addr
}

func (addr IPAddress) ToIPv6Address() IPv6Address {
	section := addr.section
	if section.matchesIPv6Address() {
		return IPv6Address{ipAddressInternal{addr}}
	}
	return IPv6Address{}
}

func (addr IPAddress) ToIPv4Address() IPv4Address {
	section := addr.section
	if section.matchesIPv4Address() {
		return IPv4Address{ipAddressInternal{addr}}
	}
	return IPv4Address{}
}

// necessary to avoid direct access to IPAddress, which when a zero value, has no segments, not compatible with zero value for ivp4 or ipv6
type ipAddressInternal struct {
	IPAddress
}

// TODO make sure everything in IPv4 and IPv6 is "overridden" so we never expose a zero value with 0 segments
// The zero values of everythign else will have sections with no segments

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
