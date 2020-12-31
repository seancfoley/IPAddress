package ipaddr

import (
	"net"
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

// TODO there are 3 other categories: []byte, uint32, SegmentValueProvider

func NewIPv4Address(section *IPv4AddressSection) *IPv4Address {
	return &IPv4Address{
		ipAddressInternal{
			addressInternal{
				section: section.ToAddressSection(),
				cache:   &addressCache{},
			},
		},
	}
}

func NewIPv4AddressFromIP(bytes net.IP) (addr *IPv4Address, err AddressValueException) {
	section, err := NewIPv4AddressSectionFromSegmentedBytes(bytes, IPv4SegmentCount)
	if err == nil {
		addr = NewIPv4Address(section)
	}
	return
}

func NewIPv4AddressFromPrefixedIP(bytes net.IP, prefixLength PrefixLen) (addr *IPv4Address, err AddressValueException) {
	section, err := NewIPv4AddressSectionFromPrefixedBytes(bytes, IPv4SegmentCount, prefixLength)
	if err == nil {
		addr = NewIPv4Address(section)
	}
	return
}

func NewIPv4AddressFromValues(vals SegmentValueProvider) (addr *IPv4Address) {
	section := NewIPv4AddressSectionFromValues(vals, IPv4SegmentCount)
	addr = NewIPv4Address(section)
	return
}

func NewIPv4AddressFromPrefixedValues(vals SegmentValueProvider, prefixLength PrefixLen) (addr *IPv4Address, err AddressValueException) {
	section, err := NewIPv4AddressSectionFromPrefixedValues(vals, IPv4SegmentCount, prefixLength)
	if err == nil {
		addr = NewIPv4Address(section)
	}
	return
}

func NewIPv4AddressFromRangeValues(vals, upperVals SegmentValueProvider) (addr *IPv4Address) {
	section := NewIPv4AddressSectionFromRangeValues(vals, upperVals, IPv4SegmentCount)
	addr = NewIPv4Address(section)
	return
}

func NewIPv4AddressFromPrefixedRangeValues(vals, upperVals SegmentValueProvider, prefixLength PrefixLen) (addr *IPv4Address, err AddressValueException) {
	section, err := NewIPv4AddressSectionFromPrefixedRangeValues(vals, upperVals, IPv4SegmentCount, prefixLength)
	if err == nil {
		addr = NewIPv4Address(section)
	}
	return
}

var zeroIPv4 *IPv4Address

func init() {
	div := NewIPv4Segment(0).ToAddressDivision()
	segs := []*AddressDivision{div, div, div, div}
	section, _ := newIPv4AddressSection(segs, false)
	zeroIPv4 = NewIPv4Address(section)
}

//
//
// IPv4Address is an IPv4 address, or a subnet of multiple IPv4 addresses.  Each segment can represent a single value or a range of values.
// The zero value is 0.0.0.0
type IPv4Address struct {
	ipAddressInternal
}

func (addr IPv4Address) String() string {
	address := addr.init()
	//TODO a different default string
	return address.ipAddressInternal.String()
}

func (addr *IPv4Address) ToAddress() *Address {
	addr = addr.init()
	return (*Address)(unsafe.Pointer(addr))
}

func (addr *IPv4Address) ToIPAddress() *IPAddress {
	addr = addr.init()
	return (*IPAddress)(unsafe.Pointer(addr))
}

func (addr *IPv4Address) init() *IPv4Address {
	if addr.section == nil {
		return zeroIPv4
	}
	return addr
}

func (addr *IPv4Address) GetSegment(index int) *IPv4AddressSegment {
	addr = addr.init()
	return addr.getSegment(index).ToIPv4AddressSegment()
}

func (addr *IPv4Address) GetIPVersion() IPVersion {
	return IPv4
}

func (addr *IPv4Address) Mask(other *IPv4Address) *IPv4Address {
	addr = addr.init()
	//TODO mask
	return nil
}

//func (addr *IPv4Address) IsSequential() bool {
//	addr = addr.init()
//	return addr.isSequential()
//}

func (addr *IPv4Address) SpanWithRange(other *IPv4Address) *IPv4AddressSeqRange {
	addr = addr.init()
	other = other.init()
	return NewIPv4SeqRange(addr, other)
}

func (addr *IPv4Address) GetLower() *IPv4Address {
	addr = addr.init()
	return addr.getLower().ToIPv4Address()
}

func (addr *IPv4Address) GetUpper() *IPv4Address {
	addr = addr.init()
	return addr.getUpper().ToIPv4Address()
}

func (addr *IPv4Address) ToSequentialRange() *IPv4AddressSeqRange {
	if addr == nil {
		return nil
	}
	addr = addr.init()
	return NewIPv4SeqRange(addr.GetLower(), addr.GetUpper())
}
