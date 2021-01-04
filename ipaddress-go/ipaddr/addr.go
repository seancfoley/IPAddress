package ipaddr

import (
	"fmt"
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

func (addr *addressInternal) getLower() *Address {
	//TODO cache the result in the addressCache
	section := addr.section.GetLower()
	if section == addr.section {
		return addr.toAddress()
	}
	return &Address{addressInternal{section: section, zone: addr.zone, cache: &addressCache{}}}
}

func (addr *addressInternal) getUpper() *Address {
	//TODO cache the result in the addressCache
	section := addr.section.GetUpper()
	if section == addr.section {
		return addr.toAddress()
	}
	return &Address{addressInternal{section: section, zone: addr.zone, cache: &addressCache{}}}
}

func (addr *addressInternal) toAddress() *Address {
	if addr == nil {
		return nil
	}
	return (*Address)(unsafe.Pointer(addr))
}

func (addr *addressInternal) hasNoDivisions() bool {
	return addr.section.hasNoDivisions()
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
		return zeroAddr // this has a zero section
	}
	return addr
}

func (addr *Address) String() string {
	addr = addr.init()
	return addr.addressInternal.String()
}

func (addr *Address) GetLower() *Address {
	addr = addr.init()
	return addr.getLower()
}

func (addr *Address) GetUpper() *Address {
	addr = addr.init()
	return addr.getUpper()
}

func (addr *Address) IsIPv4() bool {
	if addr == nil || addr.section == nil {
		return false
	}
	return addr.section.matchesIPv4Address()
}

func (addr *Address) IsIPv6() bool {
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
