package ipaddr

import (
	//"net"
	"unsafe"
)

// SegInt is an integer type for holding generic address segment values.  It is at least as large as all address segment values: IPv6SegInt, IPv4SegInt, MACSegInt
type SegInt = uint32

const SegIntSize = 32

// TODO this is where we go wrong when trying to make AddressSegment an interface
// We have a division, we want a segment, but we do not know if it conforms to MACAddressSegment or IPAddressSegment
// or some other type that implements AddressSegment, we need to know what to convert it to
// So then you might say, why do we need AddressSegment at all?  Why have a ToAddressSegment()?  Just convert to MACAddressSegment or IPAddressSegment directly?
// And Why not just use AddressDivision where-ever we'd use AddressSegment?
// Well, you need something to return from GetSegment() in type Address and AddressSection, and there are a few methods like testBit
// that apply to segments only (ie default methods in the Java AddressSegment interface)
// Also, segments use different int types than divisions
// So to be accurate we do need a segment type
// And I guess it cannot be an interface,
// there is no way to convert from our struct to an interface without knowing the specific type the interface needs to wrap
// In other words, interfaces alone cannot be used: we have no abstract methods, we actually need to have a real method,
// and while the signature could return an interface, the code would have to find a real type for that interface
// This kinda boils down to having no abstract types or methods, you have to identify a concrete type for every method
//
//func (div *AddressDivision) ToAddressSegmentX() AddressSegmentX {
//	return (AddressSegmentX)(unsafe.Pointer(div))
//}

//TODO we can enforce that any divisionValues in a IPv4 or IPv6 segment does not have too many bits to be a segmentValues
// IN other words, if you have a value like 3, it is not a segment value if it is a 64 bit value
// We can do this by ensuring that on construction of the divisionValues in NewAddressDivision by checking bit count (not magnitude)
// AddressBitsDivision does that.
// The difference in golang here is we can end up converting any division to be part of an ipv4 or ipv6 address.
// In Java you cannot go from AddressBitsDivision to IPv4 addresses.  Here you can.

//type segmentValues interface {
//	// GetSegmentValue gets the lower value for the division
//	GetSegmentValue() SegInt
//
//	// GetUpperSegmentValue gets the upper value for the division
//	GetUpperSegmentValue() SegInt
//}

//type wrappedDivisionValues struct {
//	divisionValues
//}
//
//func (segvals wrappedDivisionValues) GetSegmentValue() SegInt {
//	return SegInt(segvals.getDivisionValue())
//}
//
//func (segvals wrappedDivisionValues) GetUpperSegmentValue() SegInt {
//	return SegInt(segvals.getUpperDivisionValue())
//}

func createAddressSegment(vals divisionValues) *AddressSegment {
	return &AddressSegment{
		addressSegmentInternal{
			addressDivisionInternal{divisionValues: vals},
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

func (div *addressSegmentInternal) GetSegmentValue() SegInt {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	//return vals.(segmentValues).GetSegmentValue()
	return vals.getSegmentValue()
}

func (div *addressSegmentInternal) GetUpperSegmentValue() SegInt {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	//return vals.(segmentValues).GetUpperSegmentValue()
	return vals.getUpperSegmentValue()
}

func (div *addressSegmentInternal) IsMultiple() bool {
	vals := div.divisionValues
	if vals == nil {
		return false
	}
	//segvals := vals.(segmentValues)
	//return segvals.GetSegmentValue() != segvals.GetUpperSegmentValue()
	return vals.getSegmentValue() != vals.getUpperSegmentValue()
}

func (seg *addressSegmentInternal) GetMaxSegmentValue() SegInt {
	return ^(^SegInt(0) << seg.GetBitCount())
}

/**
 * Returns whether this item matches the value of zero
 *
 * @return whether this item matches the value of zero
 */
func (div *addressSegmentInternal) isZero() bool {
	return !div.IsMultiple() && div.IncludesZero()
}

/**
 * Returns whether this item includes the value of zero within its range
 *
 * @return whether this item includes the value of zero within its range
 */
func (div *addressSegmentInternal) IncludesZero() bool {
	return div.GetSegmentValue() == 0
}

/**
 * Returns whether this item matches the maximum possible value for the address type or version
 *
 * @return whether this item matches the maximum possible value
 */
func (div *addressSegmentInternal) isMax() bool {
	return !div.IsMultiple() && div.IncludesMax()
}

/**
 * Returns whether this item includes the maximum possible value for the address type or version within its range
 *
 * @return whether this item includes the maximum possible value within its range
 */
func (div *addressSegmentInternal) IncludesMax() bool {
	return div.GetUpperSegmentValue() == div.GetMaxSegmentValue()
}

/**
 * whether this address item represents all possible values attainable by an address item of this type
 *
 * @return whether this address item represents all possible values attainable by an address item of this type,
 * or in other words, both includesZero() and includesMax() return true
 */
func (div *addressSegmentInternal) IsFullRange() bool {
	return div.IncludesZero() && div.IncludesMax()
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

//TODO your cache will work by pairing divisionValues / divCache
// the lookup will match (a) type of ipv4SegmentValues/other (b) 3 values preflen/upper/lower
// We can simply do a comparison on the interface divisionValues - https://stackoverflow.com/questions/62944464/is-it-possible-to-compare-two-interface-values-in-go
// Well we could, but, we do return a pointer to ipv4SegmentValues, but maybe that does not matter?
// Does it compare the pointer? YES ipaddressProvider has test program
// So it cannot work that way
// I think you can do a type assertion / type switch though
// OR maybe we return the cache as part of the getLower call?
//OR we have it as a follow-up call?
//Maybe cache goes in the values?  naw, that makes no sense

//xxx figure this out
//xxx figure out cache we need a NewIPv4SegmentValues(vals) divisionValues, cache
//xxx but in this code we do not know if we are ipv4, so getLower needs to return it

func (seg *addressSegmentInternal) GetLower() *AddressSegment {
	if !seg.isMultiple() {
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
	if !seg.isMultiple() {
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

type AddressSegment struct {
	addressSegmentInternal
}

func (seg *AddressSegment) ToIPAddressSegment() *IPAddressSegment {
	if seg == nil {
		return nil
	} else if bitCount := seg.GetBitCount(); bitCount != IPv4BitsPerSegment && bitCount != IPv6BitsPerSegment {
		return nil
	}
	return (*IPAddressSegment)(unsafe.Pointer(seg))
}

func (seg *AddressSegment) ToIPv4AddressSegment() *IPv4AddressSegment {
	if seg == nil {
		return nil
	} else if bitCount := seg.GetBitCount(); bitCount != IPv4BitsPerSegment {
		return nil
	}
	return (*IPv4AddressSegment)(unsafe.Pointer(seg))
}

func (seg *AddressSegment) ToIPv6AddressSegment() *IPv6AddressSegment {
	if seg == nil {
		return nil
	} else if bitCount := seg.GetBitCount(); bitCount != IPv6BitsPerSegment {
		return nil
	}
	return (*IPv6AddressSegment)(unsafe.Pointer(seg))
}

func (seg *AddressSegment) ToMACAddressSegment() *MACAddressSegment {
	if seg == nil {
		return nil
	} else if bitCount := seg.GetBitCount(); bitCount != MACBitsPerSegment {
		return nil
	}
	return (*MACAddressSegment)(unsafe.Pointer(seg))
}

//type AddressSegmentX interface {
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

type ipAddressSegmentInternal struct {
	addressSegmentInternal
}

func (seg *ipAddressSegmentInternal) ToAddressSegment() *AddressSegment {
	return (*AddressSegment)(unsafe.Pointer(seg))
}

func (seg *ipAddressSegmentInternal) IsPrefixed() bool {
	return seg.GetSegmentPrefixLength() != nil
}

func (seg *ipAddressSegmentInternal) GetSegmentPrefixLength() PrefixLen {
	return seg.getDivisionPrefixLength()
}

type IPAddressSegment struct {
	ipAddressSegmentInternal
}

func (seg *IPAddressSegment) ContainsPrefixBlock(divisionPrefixLen BitCount) bool {
	return seg.containsPrefixBlock(divisionPrefixLen)
}

func (seg *IPAddressSegment) IsPrefixBlock() bool {
	return seg.isPrefixBlock()
}

func (seg *IPAddressSegment) IsPrefixed() bool {
	return seg.isPrefixed()
}

func (seg *IPAddressSegment) ToPrefixedNetworkSegment(segmentPrefixLength PrefixLen) *IPAddressSegment {
	return seg.ToAddressDivision().toPrefixedNetworkDivision(segmentPrefixLength).ToIPAddressSegment()
}

func (seg *IPAddressSegment) ToNetworkSegment(segmentPrefixLength PrefixLen, withPrefixLength bool) *IPAddressSegment {
	return seg.ToAddressDivision().toNetworkDivision(segmentPrefixLength, withPrefixLength).ToIPAddressSegment()
}

//	func (seg *IPAddressSegment)  ToHostSegment(segmentPrefixLength PrefixLen) *IPAddressSegment {
//	if isHostChangedByPrefix(bits) {
//		return super.toHostSegment(bits, getSegmentCreator())
//	}
//	return this
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

func segsSame(onePref, twoPref PrefixLen, oneVal, twoVal, oneUpperVal, twoUpperVal SegInt) bool {
	return PrefixEquals(onePref, twoPref) &&
		oneVal == twoVal && oneUpperVal == twoUpperVal
}

// moved to AddressDivision
//func (seg *IPAddressSegment) toNetworkSegment(segmentPrefixLength PrefixLen, withPrefixLength bool) *IPAddressSegment {
//	vals := seg.divisionValues
//	if vals == nil {
//		return seg
//	}
//	lower := seg.GetSegmentValue()
//	upper := seg.GetUpperSegmentValue()
//	var newLower, newUpper SegInt
//	hasPrefLen := segmentPrefixLength != nil
//	if hasPrefLen {
//		mask := ^SegInt(0) << (seg.GetBitCount() - *segmentPrefixLength)
//		newLower = lower & mask
//		newUpper = upper | ^mask
//		if !withPrefixLength {
//			segmentPrefixLength = nil
//		}
//		if PrefixEquals(segmentPrefixLength, seg.getDivisionPrefixLength()) &&
//			newLower == lower && newUpper == upper {
//			return seg
//		}
//	} else {
//		withPrefixLength = false
//		segmentPrefixLength = nil
//		if seg.getDivisionPrefixLength() == nil {
//			return seg
//		}
//	}
//	newVals := seg.deriveNew(DivInt(newLower), DivInt(newUpper), segmentPrefixLength)
//	return &IPAddressSegment{
//		ipAddressSegmentInternal{
//			addressSegmentInternal{
//				addressDivisionInternal{divisionValues: newVals},
//			},
//		},
//	}
//}

//func (seg *IPAddressSegment) GetDivisionPrefixLength() PrefixLen {
//	vals := seg.divisionValues
//	if vals == nil {
//		return nil
//	}
//	return vals.getDivisionPrefixLength()
//}

//// Need to prevent direct access to the IPAddressSegment, particularly when zero value
//// The IPv4 and IPv6 types need to convert the segment to the appropriate zero value with every method call that defers to IPAddressSegment
//type ipAddressSegmentInternal struct {
//	IPAddressSegment xxxx
//}
