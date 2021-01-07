package ipaddr

import (
	"net"
	"unsafe"
)

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

func NewIPv6Address(section *IPv6AddressSection) *IPv6Address {
	return NewIPv6AddressZoned(section, noZone)
}

func NewIPv6AddressZoned(section *IPv6AddressSection, zone Zone) *IPv6Address {
	return &IPv6Address{
		ipAddressInternal{
			addressInternal{
				section: section.ToAddressSection(),
				zone:    zone,
				cache:   &addressCache{},
			},
		},
	}
}

func NewIPv6AddressFromIP(bytes net.IP) (addr *IPv6Address, err AddressValueException) {
	section, err := NewIPv6AddressSectionFromSegmentedBytes(bytes, IPv6SegmentCount)
	if err == nil {
		addr = NewIPv6Address(section)
	}
	return
}

func NewIPv6AddressFromPrefixedIP(bytes []byte, prefixLength PrefixLen) (addr *IPv6Address, err AddressValueException) {
	section, err := NewIPv6AddressSectionFromPrefixedBytes(bytes, IPv6SegmentCount, prefixLength)
	if err == nil {
		addr = NewIPv6Address(section)
	}
	return
}

func NewIPv6AddressFromIPAddr(ipAddr net.IPAddr) (addr *IPv6Address, err AddressValueException) {
	addr, err = NewIPv6AddressFromIP(ipAddr.IP)
	if err == nil {
		addr.zone = Zone(ipAddr.Zone)
	}
	return
}

func NewIPv6AddressFromValues(vals SegmentValueProvider) (addr *IPv6Address) {
	section := NewIPv6AddressSectionFromValues(vals, IPv4SegmentCount)
	addr = NewIPv6Address(section)
	return
}

func NewIPv6AddressFromPrefixedValues(vals SegmentValueProvider, prefixLength PrefixLen) (addr *IPv6Address, err AddressValueException) {
	section := NewIPv6AddressSectionFromPrefixedValues(vals, IPv4SegmentCount, prefixLength)
	addr = NewIPv6Address(section)
	return
}

func NewIPv6AddressFromRange(vals, upperVals SegmentValueProvider) (addr *IPv6Address) {
	section := NewIPv6AddressSectionFromRangeValues(vals, upperVals, IPv6SegmentCount)
	addr = NewIPv6Address(section)
	return
}

func NewIPv6AddressFromPrefixedRange(vals, upperVals SegmentValueProvider, prefixLength PrefixLen) (addr *IPv6Address, err AddressValueException) {
	section := NewIPv6AddressSectionFromPrefixedRangeValues(vals, upperVals, IPv4SegmentCount, prefixLength)
	addr = NewIPv6Address(section)
	return
}

func NewIPv4AddressFromZonedRange(vals, upperVals SegmentValueProvider, zone Zone) (addr *IPv6Address) {
	section := NewIPv6AddressSectionFromRangeValues(vals, upperVals, IPv6SegmentCount)
	addr = NewIPv6AddressZoned(section, zone)
	return
}

var zeroIPv6 *IPv6Address

func init() {
	div := NewIPv6Segment(0).ToAddressDivision()
	segs := []*AddressDivision{div, div, div, div, div, div, div, div}
	section, _ := newIPv6AddressSection(segs, 0, false)
	zeroIPv6 = NewIPv6Address(section)
}

//
//
// IPv6Address is an IPv6 address, or a subnet of multiple IPv6 addresses.  Each segment can represent a single value or a range of values.
// The zero value is ::
type IPv6Address struct {
	ipAddressInternal
}

func (section *IPv6Address) GetBitCount() BitCount {
	return IPv6BitCount
}

func (section *IPv6Address) GetByteCount() int {
	return IPv6ByteCount
}

func (addr IPv6Address) String() string {
	address := addr.init()
	//TODO a different default string
	return address.addressInternal.String()
}

func (addr *IPv6Address) ToAddress() *Address {
	addr = addr.init()
	return (*Address)(unsafe.Pointer(addr))
}

func (addr *IPv6Address) ToIPAddress() *IPAddress {
	addr = addr.init()
	return (*IPAddress)(unsafe.Pointer(addr))
}

func (addr *IPv6Address) init() *IPv6Address {
	if addr.section == nil {
		return zeroIPv6
	}
	return addr
}

//func (addr *IPv6Address) IsSequential() bool {
//	addr = addr.init()
//	return addr.isSequential()
//}

func (addr *IPv6Address) GetSegment(index int) *IPv6AddressSegment {
	addr = addr.init()
	return addr.getSegment(index).ToIPv6AddressSegment()
}

func (addr *IPv6Address) GetIPVersion() IPVersion {
	return IPv6
}

func (addr *IPv6Address) Mask(other *IPv6Address) *IPv6Address {
	addr = addr.init()
	//TODO mask (handle nil gracefully, return nil)
	return nil
}

func (addr *IPv6Address) SpanWithRange(other *IPv6Address) *IPv6AddressSeqRange {
	addr = addr.init()
	return NewIPv6SeqRange(addr, other)
}

func (addr *IPv6Address) GetLower() *IPv6Address {
	addr = addr.init()
	return addr.getLower().ToIPv6Address()
}

func (addr *IPv6Address) GetUpper() *IPv6Address {
	addr = addr.init()
	return addr.getUpper().ToIPv6Address()
}

func (addr *IPv6Address) ToPrefixBlock() *IPv6Address {
	addr = addr.init()
	return addr.ToIPAddress().ToPrefixBlock().ToIPv6Address()
}

func (addr *IPv6Address) ToPrefixBlockLen(prefLen BitCount) *IPv6Address {
	addr = addr.init()
	return addr.ToIPAddress().ToPrefixBlockLen(prefLen).ToIPv6Address()
}

func (addr *IPv6Address) GetBytes() net.IP {
	addr = addr.init()
	return addr.section.GetBytes()
}

func (addr *IPv6Address) CopyBytes(bytes net.IP) net.IP {
	addr = addr.init()
	return addr.section.CopyBytes(bytes)
}

func (addr *IPv6Address) GetUpperBytes() net.IP {
	addr = addr.init()
	return addr.section.GetUpperBytes()
}

func (addr *IPv6Address) CopyUpperBytes(bytes net.IP) net.IP {
	addr = addr.init()
	return addr.section.CopyUpperBytes(bytes)
}

func (addr *IPv6Address) ToSequentialRange() *IPv6AddressSeqRange {
	if addr == nil {
		return nil
	}
	addr = addr.init()
	return NewIPv6SeqRange(addr.GetLower(), addr.GetUpper())
}
