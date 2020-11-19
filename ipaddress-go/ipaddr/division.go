package ipaddr

import "unsafe"

// SegInt is an unsigned integer type for holding generic segment values, which are unsigned byte for MAC or IPv4 and two unsigned bytes for IPv6.
type SegInt = uint16

// DivInt is an unsigned integer type for division values, aliased to the largest unsigned primitive type to allow for the largest possible division values.
type DivInt = uint64

type divisionValuesBase interface { // shared by standard and large divisions
	GetBitCount() BitCount

	GetByteCount() int
}

// DivisionValues represents divisions with values that are 64 bits or less
type divisionValues interface {
	divisionValuesBase

	// GetDivisionValue gets the lower value for the division
	GetDivisionValue() DivInt

	// GetUpperDivisionValue gets the upper value for the division
	GetUpperDivisionValue() DivInt

	getDivisionPrefixLength() PrefixLen
}

//TODO we can enforce that any divisionValues in a IPv4 or IPv6 segment is also a segmentValues
// We can do this by ensuring that on construction of the divisionValues in NewAddressDivision by checking bit count (not magnitude)
// AddressBitsDivision does that.
// The difference in golang here is we can end up converting any division to be part of an ipv4 or ipv6 address.
// In Java you cannot go from AddressBitsDivision to IPv4 addresses.  Here you can.

type segmentValues interface {
	// GetSegmentValue gets the lower value for the division
	GetSegmentValue() SegInt

	// GetUpperSegmentValue gets the upper value for the division
	GetUpperSegmentValue() SegInt

	GetSegmentPrefixLength() PrefixLen
}

type addressDivisionInternal struct {
	divisionValues

	// TODO we will have more fields, such as cached strings and bytes
}

func (div *addressDivisionInternal) GetBitCount() BitCount {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.GetBitCount()
}

func (div *addressDivisionInternal) GetByteCount() int {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.GetByteCount()
}

func (div *addressDivisionInternal) GetDivisionValue() DivInt {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.GetDivisionValue()
}

func (div *addressDivisionInternal) GetUpperDivisionValue() DivInt {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.GetUpperDivisionValue()
}

type AddressDivision struct {
	addressDivisionInternal
}

func (div *AddressDivision) ToAddressSegment() *AddressSegment {
	return (*AddressSegment)(unsafe.Pointer(div))
}

func (div *AddressDivision) ToIPAddressSegment() *IPAddressSegment {
	return div.ToAddressSegment().ToIPAddressSegment()
}

func (div *AddressDivision) ToIPv4AddressSegment() *IPv4AddressSegment {
	return div.ToAddressSegment().ToIPv4AddressSegment()
}

func (div *AddressDivision) ToIPv6AddressSegment() *IPv6AddressSegment {
	return div.ToAddressSegment().ToIPv6AddressSegment()
}

func (div *AddressDivision) ToMACAddressSegment() *MACAddressSegment {
	return div.ToAddressSegment().ToMACAddressSegment()
}

type addressSegmentInternal struct {
	addressDivisionInternal
}

func (div *addressSegmentInternal) GetSegmentValue() SegInt {
	vals := div.divisionValues.(segmentValues)
	if vals == nil {
		return 0
	}
	return vals.GetSegmentValue()
}

func (div *addressSegmentInternal) GetUpperSegmentValue() SegInt {
	vals := div.divisionValues.(segmentValues)
	if vals == nil {
		return 0
	}
	return vals.GetUpperSegmentValue()
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

type AddressSegment struct {
	addressSegmentInternal
}

func (div *AddressSegment) ToIPAddressSegment() *IPAddressSegment {
	if div == nil {
		return nil
	} else if bitCount := div.GetBitCount(); bitCount != IPv4BitsPerSegment && bitCount != IPv6BitsPerSegment {
		return nil
	}
	return (*IPAddressSegment)(unsafe.Pointer(div))
}

func (div *AddressSegment) ToIPv4AddressSegment() *IPv4AddressSegment {
	if div == nil {
		return nil
	} else if bitCount := div.GetBitCount(); bitCount != IPv4BitsPerSegment {
		return nil
	}
	return (*IPv4AddressSegment)(unsafe.Pointer(div))
}

func (div *AddressSegment) ToIPv6AddressSegment() *IPv6AddressSegment {
	if div == nil {
		return nil
	} else if bitCount := div.GetBitCount(); bitCount != IPv6BitsPerSegment {
		return nil
	}
	return (*IPv6AddressSegment)(unsafe.Pointer(div))
}

func (div *AddressSegment) ToMACAddressSegment() *MACAddressSegment {
	if div == nil {
		return nil
	} else if bitCount := div.GetBitCount(); bitCount != MACBitsPerSegment {
		return nil
	}
	return (*MACAddressSegment)(unsafe.Pointer(div))
}

type ipAddressSegmentInternal struct {
	addressSegmentInternal
}

//type AddressSegment interface {
//}
//
//func (div *AddressDivision) ToIPAddressSegment() *IPAddressSegment {
//	if div == nil {
//		return nil
//	} else if bitCount := div.GetBitCount(); bitCount != IPv4BitsPerSegment && bitCount != IPv6BitsPerSegment {
//		return nil
//	}
//	return (*IPAddressSegment)(unsafe.Pointer(div))
//}
//
//func (div *AddressDivision) ToIPv4AddressSegment() *IPv4AddressSegment {
//	if div == nil {
//		return nil
//	} else if bitCount := div.GetBitCount(); bitCount != IPv4BitsPerSegment {
//		return nil
//	}
//	return (*IPv4AddressSegment)(unsafe.Pointer(div))
//}
//
//func (div *AddressDivision) ToIPv6AddressSegment() *IPv6AddressSegment {
//	if div == nil {
//		return nil
//	} else if bitCount := div.GetBitCount(); bitCount != IPv6BitsPerSegment {
//		return nil
//	}
//	return (*IPv6AddressSegment)(unsafe.Pointer(div))
//}
//
//func (div *AddressDivision) ToMACAddressSegment() *MACAddressSegment {
//	if div == nil {
//		return nil
//	} else if bitCount := div.GetBitCount(); bitCount != MACBitsPerSegment {
//		return nil
//	}
//	return (*MACAddressSegment)(unsafe.Pointer(div))
//}

//type ipAddressSegmentInternal struct {
//	addressDivisionInternal
//}

//type IPAddressSegment struct {
//	addressDivisionInternal
//}

type IPAddressSegment struct {
	ipAddressSegmentInternal
}

func (seg *IPAddressSegment) ToAddressDivision() *AddressDivision {
	return (*AddressDivision)(unsafe.Pointer(seg))
}

//func (seg *IPAddressSegment) ToIPAddressSegment() *IPAddressSegment {
//	return seg
//}

func (seg *IPAddressSegment) ToIPv4AddressSegment() *IPv4AddressSegment {
	if seg == nil {
		return nil
	} else if bitCount := seg.GetBitCount(); bitCount != IPv4BitsPerSegment {
		return nil
	}
	return (*IPv4AddressSegment)(unsafe.Pointer(seg))
}

func (seg *IPAddressSegment) ToIPv6AddressSegment() *IPv6AddressSegment {
	if seg == nil {
		return nil
	} else if bitCount := seg.GetBitCount(); bitCount != IPv6BitsPerSegment {
		return nil
	}
	return (*IPv6AddressSegment)(unsafe.Pointer(seg))
}

func (seg *IPAddressSegment) GetDivisionPrefixLength() PrefixLen {
	vals := seg.divisionValues
	if vals == nil {
		return nil
	}
	return vals.getDivisionPrefixLength()
}

//// Need to prevent direct access to the IPAddressSegment, particularly when zero value
//// The IPv4 and IPv6 types need to convert the segment to the appropriate zero value with every method call that defers to IPAddressSegment
//type ipAddressSegmentInternal struct {
//	IPAddressSegment xxxx
//}
