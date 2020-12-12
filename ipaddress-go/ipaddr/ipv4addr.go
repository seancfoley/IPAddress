package ipaddr

import (
	//"net"
	"unsafe"
)

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
// IPv4Address is an IPv4 address, or a subnet of multiple IPv4 addresses.  Each segment can represent a single value or a range of values.
// The zero value is 0.0.0.0
type IPv4Address struct {
	ipAddressInternal
}

func (addr IPv4Address) init() {
	if addr.hasNoDivisions() {
		div := NewIPv4Segment(0).ToAddressDivision()
		addr.section = AddressSection{
			addressSectionInternal{
				addressDivisionGroupingInternal{
					divisions: []*AddressDivision{div, div, div, div},
					cache:     &valueCache{addrType: ipv4AddrType},
				},
			},
		}
		addr.cache = &addressCache{}
	}
}

func (addr *IPv4Address) GetSegment(index int) *IPv4AddressSegment {
	addr.init()
	return addr.ipAddressInternal.GetSegment(index).ToIPv4AddressSegment()
}

func (addr *IPv4Address) GetIPVersion() IPVersion {
	return IPv4
}

func (addr *IPv4Address) ToAddress() *Address {
	addr.init()
	return (*Address)(unsafe.Pointer(addr))
}

func (addr *IPv4Address) ToIPAddress() *IPAddress {
	addr.init()
	return (*IPAddress)(unsafe.Pointer(addr))
}

//func (addr *IPv4Address) IsIPv6Convertible() bool {
//	addr.init()
//	return addr.getConverter().IsIPv6Convertible(addr.ToIPAddress())
//}
//
//func (addr *IPv4Address) ToIPv6Address() *IPv6Address {
//	addr.init()
//	return addr.getConverter().ToIPv6(addr.ToIPAddress())
//}

func (addr *IPv4Address) Mask(other *IPv4Address) *IPv4Address {
	//TODO mask (handle nil gracefully, return nil)
	return nil
}

func (addr *IPv4Address) SpanWithRange(other *IPv4Address) *IPv4AddressSeqRange {
	addr.init()
	return NewIPv4SeqRange(addr, other)
}

func (addr *IPv4Address) GetLower() *IPv4Address {
	addr.init()
	return addr.ToAddress().GetLower().ToIPv4Address()
}

func (addr *IPv4Address) GetUpper() *IPv4Address {
	addr.init()
	return addr.ToAddress().GetUpper().ToIPv4Address()
}

func (addr *IPv4Address) ToSequentialRange() *IPv4AddressSeqRange {
	if addr != nil {
		return NewIPv4SeqRange(addr.GetLower(), addr.GetUpper())
	}
	return nil
}
