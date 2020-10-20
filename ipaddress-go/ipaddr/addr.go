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
		return IPAddress{addressInternal{addr}}
	}
	return IPAddress{}
}

func (addr Address) ToIPv6Address() IPv6Address {
	return addr.ToIPAddress().ToIPv6Address()
}

func (addr Address) ToIPv4Address() IPv4Address {
	return addr.ToIPAddress().ToIPv4Address()
}

type addressInternal struct {
	Address
}

//
//
//
type IPAddress struct {
	addressInternal
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

// TODO make sure everything in IPv4 and IPv6 is "overridden", in the sense all methods will check for no divisions and
// create the default zero-segments if necessary, so we never expose a zero value with 0 segments
// The zero values of everythign else will have sections with no segments
