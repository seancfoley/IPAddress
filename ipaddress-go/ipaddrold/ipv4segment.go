package ipaddrold

import (
	"math/big"
)

type ipv4SegmentValues struct {
	divisionValue      uint8
	upperDivisionValue uint8
	prefix             *PrefixLen
}

func (d *ipv4SegmentValues) GetDivisionValue() DivInt {
	return DivInt(d.divisionValue)
}

func (d *ipv4SegmentValues) GetUpperDivisionValue() DivInt {
	return DivInt(d.upperDivisionValue)
}

func (d *ipv4SegmentValues) getDivisionPrefixLength() *PrefixLen {
	return d.prefix
}

func (d *ipv4SegmentValues) GetValue() *BigDivInt {
	return big.NewInt(int64(d.divisionValue))
}

func (d *ipv4SegmentValues) GetUpperValue() *BigDivInt {
	return big.NewInt(int64(d.upperDivisionValue))
}

func (d *ipv4SegmentValues) GetBitCount() int {
	return 8 //TODO make constants
}

func (d *ipv4SegmentValues) GetByteCount() int {
	return 1 //TODO make constants
}

// IPv4AddressSegment is a segment in an IPv4 address or address section
type IPv4AddressSegment struct {
	ipAddressSegmentInternal
}

func (d *IPv4AddressSegment) assignDefaultValues() {
	if d.divisionValues == nil {
		d.divisionValues = &ipv4SegmentValues{}
	}
}

//func (d *IPv4AddressSegment) assignIPv4Values() {
//	if d.divisionValues == nil {
//		d.divisionValues = &ipv4SegmentValues{}
//	}
//}

func (d *IPv4AddressSegment) ToIPSegment() *IPAddressSegment {
	d.assignDefaultValues()
	return &IPAddressSegment{d.ipAddressSegmentInternal}
}

// ToIPv4() return this segment
//func (d *IPv4AddressSegment) ToIPv4() *IPv4AddressSegment {
//	return d
//}

// ToIPv6() returns nil
//func (d *IPv4AddressSegment) ToIPv6() *IPv6AddressSegment {
//	return nil
//}

func (d *IPv4AddressSegment) GetBitCount() int {
	d.assignDefaultValues()
	return d.divisionValues.GetBitCount()
}

func (d *IPv4AddressSegment) GetByteCount() int {
	d.assignDefaultValues()
	return d.divisionValues.GetByteCount()
}
