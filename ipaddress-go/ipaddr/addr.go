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
