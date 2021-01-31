package ipaddr

import (
	"unsafe"
)

// SegInt is an integer type for holding generic address segment values.  It is at least as large as all address segment values: IPv6SegInt, IPv4SegInt, MACSegInt
type SegInt = uint32
type SegIntCount = uint64

const SegIntSize = 32

func createAddressSegment(vals divisionValues) *AddressSegment {
	return &AddressSegment{
		addressSegmentInternal{
			addressDivisionInternal{
				addressDivisionBase{
					divisionValues: vals,
				},
			},
		},
	}
}

type addressSegmentInternal struct {
	addressDivisionInternal
}

func (seg *addressSegmentInternal) toAddressSegment() *AddressSegment {
	return (*AddressSegment)(unsafe.Pointer(seg))
}

func (seg *addressSegmentInternal) ToAddressDivision() *AddressDivision {
	return (*AddressDivision)(unsafe.Pointer(seg))
}

func (seg *addressSegmentInternal) GetSegmentValue() SegInt {
	vals := seg.divisionValues
	if vals == nil {
		return 0
	}
	return vals.getSegmentValue()
}

func (seg *addressSegmentInternal) GetUpperSegmentValue() SegInt {
	vals := seg.divisionValues
	if vals == nil {
		return 0
	}
	return vals.getUpperSegmentValue()
}

//func (seg *addressSegmentInternal) GetDivisionValue() DivInt {
//	return seg.getDivisionValue()
//}
//
//func (seg *addressSegmentInternal) GetUpperDivisionValue() DivInt {
//	return seg.getUpperDivisionValue()
//}

func (seg *addressSegmentInternal) GetValueCount() SegIntCount {
	return uint64(seg.GetUpperSegmentValue()-seg.GetSegmentValue()) + 1
}

func (seg *addressSegmentInternal) GetMaxValue() SegInt {
	return ^(^SegInt(0) << seg.GetBitCount())
}

// Computes (this &amp; (1 &lt;&lt; n)) != 0), using the lower value of this segment.
func (div *addressSegmentInternal) TestBit(n BitCount) bool {
	value := div.GetSegmentValue()
	return (value & (1 << n)) != 0
}

// Returns true if the bit in the lower value of this segment at the given index is 1, where index 0 is the most significant bit.
func (div *addressSegmentInternal) isOneBit(segmentBitIndex BitCount) bool {
	value := div.GetSegmentValue()
	bitCount := div.GetBitCount()
	return (value & (1 << (bitCount - (segmentBitIndex + 1)))) != 0
}

func (seg *addressSegmentInternal) GetLower() *AddressSegment {
	if !seg.IsMultiple() {
		return seg.toAddressSegment()
	}
	vals := seg.divisionValues
	var newVals divisionValues
	if vals != nil {
		newVals = seg.deriveNew(seg.getDivisionValue(), seg.getDivisionValue(), seg.getDivisionPrefixLength())
	}
	return createAddressSegment(newVals)
}

func (seg *addressSegmentInternal) GetUpper() *AddressSegment {
	if !seg.IsMultiple() {
		return seg.toAddressSegment()
	}
	//vals, cache := seg.getUpper()
	vals := seg.divisionValues
	var newVals divisionValues
	if vals != nil {
		newVals = seg.deriveNew(seg.getUpperDivisionValue(), seg.getUpperDivisionValue(), seg.getDivisionPrefixLength())
	}
	return createAddressSegment(newVals)
}

func (seg *addressSegmentInternal) matchesIPSegment() bool {
	if bitCount := seg.GetBitCount(); bitCount != IPv4BitsPerSegment && bitCount != IPv6BitsPerSegment {
		return false
	}
	return true
}

func (seg *addressSegmentInternal) matchesIPv4Segment() bool {
	return seg.GetBitCount() == IPv4BitsPerSegment
}

func (seg *addressSegmentInternal) matchesIPv6Segment() bool {
	return seg.GetBitCount() == IPv6BitsPerSegment
}

func (seg *addressSegmentInternal) matchesMACSegment() bool {
	return seg.GetBitCount() == MACBitsPerSegment
}

type AddressSegment struct {
	addressSegmentInternal
}

// TODO segments work different than sections, and we must be careful with methods returning strings that they remain consistent
// Unlike with sections, we have no addrType to check, but since segments are printed withut separators, mostly ok,
// but then there is the radix to worry about, also the prefix to worry about.
// Methods that use the prefix to print the string must not use any shared fields with AddressSegment and AddressDivision
// Methods that print strings in hex must not share fields with IPv4AddressSegment

func (seg *AddressSegment) IsIPAddressSegment() bool {
	return seg != nil && seg.matchesIPSegment()
}

func (seg *AddressSegment) IsIPv4AddressSegment() bool { //TODO maybe rename all these to IsIPv4(), same for IPv6() and maybe isMAC()
	return seg != nil && seg.matchesIPv4Segment()
}

func (seg *AddressSegment) IsIPv6AddressSegment() bool {
	return seg != nil && seg.matchesIPv6Segment()
}

func (seg *AddressSegment) IsMACAddressSegment() bool {
	return seg != nil && seg.matchesMACSegment()
}

func (seg *AddressSegment) ToIPAddressSegment() *IPAddressSegment {
	if seg.IsIPAddressSegment() {
		return (*IPAddressSegment)(unsafe.Pointer(seg))
	}
	return nil
}

func (seg *AddressSegment) ToIPv4AddressSegment() *IPv4AddressSegment {
	if seg.IsIPv4AddressSegment() {
		return (*IPv4AddressSegment)(unsafe.Pointer(seg))
	}
	return nil
}

func (seg *AddressSegment) ToIPv6AddressSegment() *IPv6AddressSegment {
	if seg.IsIPv6AddressSegment() {
		return (*IPv6AddressSegment)(unsafe.Pointer(seg))
	}
	return nil
}

func (seg *AddressSegment) ToMACAddressSegment() *MACAddressSegment {
	if seg.IsMACAddressSegment() {
		return (*MACAddressSegment)(unsafe.Pointer(seg))
	}
	return nil
}
