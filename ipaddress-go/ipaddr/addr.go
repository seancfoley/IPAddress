package ipaddr

import (
	"fmt"
	"math/big"
	"net"
	"unsafe"
)

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

type SegmentValueProvider func(segmentIndex int) SegInt

type addressCache struct {
	ip           net.IPAddr // lower converted (cloned when returned)
	lower, upper *Address
}

type addressInternal struct {
	section *AddressSection
	zone    Zone
	cache   *addressCache
}

func (addr *addressInternal) GetBitCount() BitCount {
	if addr.section == nil {
		return 0
	}
	return addr.section.GetBitCount()
}

func (addr *addressInternal) GetByteCount() int {
	if addr.section == nil {
		return 0
	}
	return addr.section.GetByteCount()
}

func (addr *addressInternal) GetCount() *big.Int {
	if addr.section == nil {
		return bigOne()
	}
	return addr.section.GetCount()
}

func (addr *addressInternal) IsMultiple() bool {
	if addr.section == nil {
		return false
	}
	return addr.section.IsMultiple()
}

func (addr *addressInternal) isMore(other *Address) int {
	if addr.section == nil {
		if other.IsMultiple() {
			return -1
		}
		return 0
	}
	return addr.section.IsMore(other.GetSection())
}

func (addr addressInternal) String() string { // using non-pointer receiver makes it work well with fmt
	if addr.zone != noZone {
		return fmt.Sprintf("%v%c%s", addr.section, IPv6ZoneSeparator, addr.zone)
	}
	return fmt.Sprintf("%v", addr.section)
}

func (addr *addressInternal) IsSequential() bool {
	if addr.section == nil {
		return true
	}
	return addr.section.IsSequential()
}

func (addr *addressInternal) getSegment(index int) *AddressSegment {
	return addr.section.GetSegment(index)
}

func (addr *addressInternal) GetValue() *big.Int {
	if addr.section == nil {
		return bigZero()
	}
	return addr.section.GetValue()
}

func (addr *addressInternal) GetUpperValue() *big.Int {
	if addr.section == nil {
		return bigZero()
	}
	return addr.section.GetUpperValue()
}

func (addr *addressInternal) GetBytes() net.IP {
	if addr.section == nil {
		return emptyBytes
	}
	return addr.section.GetBytes()
}

func (addr *addressInternal) CopyBytes(bytes net.IP) net.IP {
	if addr.section == nil {
		if bytes != nil {
			return bytes
		}
		return emptyBytes
	}
	return addr.section.CopyBytes(bytes)
}

func (addr *addressInternal) GetUpperBytes() net.IP {
	if addr.section == nil {
		return emptyBytes
	}
	return addr.section.GetUpperBytes()
}

func (addr *addressInternal) CopyUpperBytes(bytes net.IP) net.IP {
	if addr.section == nil {
		if bytes != nil {
			return bytes
		}
		return emptyBytes
	}
	return addr.section.CopyUpperBytes(bytes)
}

func (addr *addressInternal) checkIdentity(section *AddressSection) *Address {
	if section == addr.section {
		return addr.toAddress()
	}
	return &Address{addressInternal{section: section, zone: addr.zone, cache: &addressCache{}}}
}

func (addr *addressInternal) getLower() *Address {
	//TODO cache the result in the addressCache
	return addr.checkIdentity(addr.section.GetLower())
}

func (addr *addressInternal) getUpper() *Address {
	//TODO cache the result in the addressCache
	return addr.checkIdentity(addr.section.GetUpper())
}

func (addr *addressInternal) toAddress() *Address {
	return (*Address)(unsafe.Pointer(addr))
}

func (addr *addressInternal) hasNoDivisions() bool {
	return addr.section.hasNoDivisions()
}

func (addr *addressInternal) toPrefixBlock() *Address {
	return addr.checkIdentity(addr.section.toPrefixBlock())
}

func (addr *addressInternal) toPrefixBlockLen(prefLen BitCount) *Address {
	return addr.checkIdentity(addr.section.toPrefixBlockLen(prefLen))
}

var zeroAddr *Address

func init() {
	zeroAddr = &Address{
		addressInternal{
			section: &AddressSection{},
			cache:   &addressCache{},
		},
	}
}

type Address struct {
	addressInternal
}

func (addr *Address) init() *Address {
	if addr.section == nil {
		return zeroAddr // this has a zero section rather that a nil section
	}
	return addr
}

func (addr *Address) String() string {
	return addr.init().addressInternal.String()
}

func (addr *Address) GetSection() *AddressSection {
	return addr.init().section
}

// Gets the subsection from the series starting from the given index
// The first segment is at index 0.
func (addr *Address) GetTrailingSection(index int) *AddressSection {
	return addr.GetSection().GetTrailingSection(index)
}

//// Gets the subsection from the series starting from the given index and ending just before the give endIndex
//// The first segment is at index 0.
func (addr *Address) GetSubSection(index, endIndex int) *AddressSection {
	return addr.GetSection().GetSubSection(index, endIndex)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (addr *Address) CopySubSegments(start, end int, segs []*AddressSegment) (count int) {
	return addr.GetSection().CopySubSegments(start, end, segs)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (addr *Address) CopySegments(segs []*AddressSegment) (count int) {
	return addr.GetSection().CopySegments(segs)
}

// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this section.
func (addr *Address) GetSegments() []*AddressSegment {
	return addr.GetSection().GetSegments()
}

func (addr *Address) GetLower() *Address {
	return addr.init().getLower()
}

func (addr *Address) GetUpper() *Address {
	return addr.init().getUpper()
}

func (addr *Address) ToPrefixBlock() *Address {
	return addr.init().toPrefixBlock()
}

func (addr *Address) IsIPv4() bool { // we allow nil receivers to allow this to be called following a failed converion like ToIPAddress()
	if addr == nil || addr.section == nil {
		return false
	}
	return addr.section.matchesIPv4Address()
}

func (addr *Address) IsIPv6() bool { // we allow nil receivers to allow this to be called following a failed converion like ToIPAddress()
	if addr == nil || addr.section == nil {
		return false
	}
	return addr.section.matchesIPv6Address()
}

func (addr *Address) ToIPAddress() *IPAddress {
	if addr == nil {
		return nil
	} else {
		addr = addr.init()
		if addr.hasNoDivisions() /* the zero IPAddress */ ||
			addr.section.matchesIPv4Address() || addr.section.matchesIPv6Address() {
			return (*IPAddress)(unsafe.Pointer(addr))
		}
	}
	return nil
}

func (addr *Address) ToIPv6Address() *IPv6Address {
	if addr == nil {
		return nil
	} else {
		addr = addr.init()
		if addr.section.matchesIPv6Address() {
			return (*IPv6Address)(unsafe.Pointer(addr))
		}
	}
	return nil
}

func (addr *Address) ToIPv4Address() *IPv4Address {
	if addr == nil {
		return nil
	} else {
		addr = addr.init()
		if addr.section.matchesIPv4Address() {
			return (*IPv4Address)(unsafe.Pointer(addr))
		}
	}
	return nil
}

func (addr *Address) ToMACAddress() *MACAddress {
	if addr == nil {
		return nil
	} else {
		addr = addr.init()
		if addr.section.matchesMACAddress() {
			return (*MACAddress)(unsafe.Pointer(addr))
		}
	}
	return nil
}
