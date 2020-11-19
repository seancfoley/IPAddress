package ipaddr

import "unsafe"

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

func (zone Zone) IsEmpty() bool {
	return zone == ""
}

const noZone Zone = ""

//
//
// IPv6Address is an IPv6 address, or a subnet of multiple IPv6 addresses.  Each segment can represent a single value or a range of values.
// The zero value is ::
type IPv6Address struct {
	ipAddressInternal
}

func (addr IPv6Address) init() {
	if addr.hasNoDivisions() {
		div := NewIPv6Segment(0).ToAddressDivision()
		addr.section = AddressSection{
			addressSectionInternal{
				addressDivisionGroupingInternal{
					divisions: []*AddressDivision{div, div, div, div, div, div, div, div},
				},
			},
		}
	}
}

func (addr *IPv6Address) GetSegment(index int) *IPv6AddressSegment {
	addr.init()
	return addr.ipAddressInternal.GetSegment(index).ToIPv6AddressSegment()
}

func (addr *IPv6Address) IsIPv4() bool {
	return false
}

func (addr *IPv6Address) IsIPv6() bool {
	return true
}

func (addr *IPv6Address) GetIPVersion() IPVersion {
	return IPv6
}

func (addr *IPv6Address) ToAddress() *Address {
	addr.init()
	return (*Address)(unsafe.Pointer(addr))
}

func (addr *IPv6Address) ToIPAddress() *IPAddress {
	addr.init()
	return (*IPAddress)(unsafe.Pointer(addr))
}

func (addr *IPv6Address) IsIPv4Convertible() bool {
	//TODO conversion
	return false
}

func (addr *IPv6Address) ToIPv4Address() *IPv4Address {
	//addr.init()
	//TODO conversion
	return nil
}
