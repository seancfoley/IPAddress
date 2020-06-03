package ipaddrold

import (
	//"fmt"
	"math/big"
)

type ipv6SegmentValues struct {
	divisionValue      uint16
	upperDivisionValue uint16
	prefix             *PrefixLen
}

func (d *ipv6SegmentValues) GetDivisionValue() DivInt {
	return DivInt(d.divisionValue)
}

func (d *ipv6SegmentValues) GetUpperDivisionValue() DivInt {
	return DivInt(d.upperDivisionValue)
}

func (d *ipv6SegmentValues) getDivisionPrefixLength() *PrefixLen {
	return d.prefix
}

func (d *ipv6SegmentValues) GetValue() *BigDivInt {
	return big.NewInt(int64(d.divisionValue))
}

func (d *ipv6SegmentValues) GetUpperValue() *BigDivInt {
	return big.NewInt(int64(d.upperDivisionValue))
}

func (d *ipv6SegmentValues) GetBitCount() int {
	return 16 //TODO make constants
}

func (d *ipv6SegmentValues) GetByteCount() int {
	return 2 //TODO make constants
}

// IPv6AddressSegment is a segment in an IPv6 address or address section
type IPv6AddressSegment struct {
	ipAddressSegmentInternal
}

func (d *IPv6AddressSegment) assignDefaultValues() {
	if d.divisionValues == nil {
		d.divisionValues = &ipv6SegmentValues{}
	}
}

//func (d *IPv6AddressSegment) assignIPv6Values() {
//	if d.divisionValues == nil {
//		d.divisionValues = &ipv6SegmentValues{}
//	}
//}

func (d *IPv6AddressSegment) ToIPSegment() *IPAddressSegment {
	d.assignDefaultValues()
	return &IPAddressSegment{d.ipAddressSegmentInternal}
}

// ToIPv6() returns this segment
//func (d *IPv6AddressSegment) ToIPv6() *IPv6AddressSegment {
//	return d
//}

// ToIPv4() returns nil
//func (d *IPv6AddressSegment) ToIPv4() *IPv4AddressSegment {
//	return nil
//}

func (d *IPv6AddressSegment) GetBitCount() int {
	d.assignDefaultValues()
	return d.divisionValues.GetBitCount()
}

func (d *IPv6AddressSegment) GetByteCount() int {
	d.assignDefaultValues()
	return d.divisionValues.GetByteCount()
}

//func (d *IPv6AddressSegment) getSplitSegments() {
//	s := d.GetSegmentValue()
//	t := d.GetDivisionPrefixLength()
//	fmt.Printf("%d %d", s, *t)
//}
