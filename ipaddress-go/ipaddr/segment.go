package ipaddr

import (
	"unsafe"
)

// SegInt is an integer type for holding generic address segment values.  It is at least as large as all address segment values: IPv6SegInt, IPv4SegInt, MACSegInt
type SegInt = uint32      // must be at least uint16 to handle IPv6, at least 32 to handle single segment IPv4, and no larger than 64 because we use bits.TrailingZeros64.  IP address segment code uses bits.TrailingZeros32 and bits.LeadingZeros32, so it cannot be larger than 32.
const SegIntSize = 32     // must match the bit count of SegInt
type SegIntCount = uint64 // must be able to hold: (max value of SegInt) + 1

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

func (seg *addressSegmentInternal) Contains(other AddressStandardSegment) (res bool) {
	// TODO an identity/pointer comparison which requires we grab the *addressDivisionInternal or *addressDivisionBase or *addressSegmentInternal from AddressStandardSegment
	if matchesStructure, _ := seg.matchesStructure(other); matchesStructure {
		otherSeg := other.ToAddressSegment()
		res = otherSeg.GetSegmentValue() >= seg.GetSegmentValue() &&
			otherSeg.GetUpperSegmentValue() <= seg.GetUpperSegmentValue()
	}
	return
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
		newVals = seg.deriveNewMultiSeg(seg.GetSegmentValue(), seg.GetSegmentValue(), seg.getDivisionPrefixLength())
	}
	return createAddressSegment(newVals)
}

func (seg *addressSegmentInternal) GetUpper() *AddressSegment {
	if !seg.IsMultiple() {
		return seg.toAddressSegment()
	}
	vals := seg.divisionValues
	var newVals divisionValues
	if vals != nil {
		newVals = seg.deriveNewMultiSeg(seg.GetUpperSegmentValue(), seg.GetUpperSegmentValue(), seg.getDivisionPrefixLength())
	}
	return createAddressSegment(newVals)
}

func (seg *addressSegmentInternal) getDefaultSegmentWildcardString() string {
	return SegmentWildcardStr
}

func (seg *addressSegmentInternal) iterator() SegmentIterator {
	return seg.segmentIterator(seg.getDivisionPrefixLength(), false, false)
}

func (seg *addressSegmentInternal) identityIterator() SegmentIterator {
	return &singleSegmentIterator{original: seg.toAddressSegment()}
}

//func (seg *addressSegmentInternal) iter(withPrefix bool) SegmentIterator { TODO might not need this
//	var segPrefLen PrefixLen
//	if withPrefix {
//		segPrefLen = seg.getDivisionPrefixLength()
//	}
//	return seg.segmentIterator(segPrefLen, false, false)
//}

func (seg *addressSegmentInternal) prefixBlockIterator() SegmentIterator {
	return seg.segmentIterator(seg.getDivisionPrefixLength(), true, true)
}

func (seg *addressSegmentInternal) prefixedBlockIterator(segPrefLen BitCount) SegmentIterator {
	return seg.segmentIterator(cacheBitCount(segPrefLen), true, true)
}

func (seg *addressSegmentInternal) prefixIterator() SegmentIterator {
	return seg.segmentIterator(seg.getDivisionPrefixLength(), true, false)
}

func (seg *addressSegmentInternal) prefixedIterator(segPrefLen BitCount) SegmentIterator {
	return seg.segmentIterator(cacheBitCount(segPrefLen), true, false)
}

func (seg *addressSegmentInternal) segmentIterator(segPrefLen PrefixLen, isPrefixIterator, isBlockIterator bool) SegmentIterator {
	vals := seg.divisionValues
	if vals == nil {
		return segIterator(seg,
			0,
			0,
			0,
			nil,
			nil,
			false,
			false,
		)
	}
	return segIterator(seg,
		seg.getSegmentValue(),
		seg.getUpperSegmentValue(),
		seg.getBitCount(),
		vals,
		segPrefLen,
		isPrefixIterator,
		isBlockIterator,
	)
}

var (
	// wildcards differ, for divs we use only range since div size not implicit, here we use both range and *
	hexParamsSeg     = new(IPStringOptionsBuilder).SetRadix(16).SetSegmentStrPrefix(HexPrefix).ToOptions()
	decimalParamsSeg = new(IPStringOptionsBuilder).SetRadix(10).ToOptions()
)

func (seg *addressSegmentInternal) ToNormalizedString() string {
	stringer := func() string {
		switch seg.getDefaultTextualRadix() {
		case 10:
			return seg.toString(decimalParamsSeg)
		default:
			return seg.toString(macCompressedParams)
		}
	}
	if seg.divisionValues != nil {
		if cache := seg.getCache(); cache != nil {
			return cacheStr(&cache.cachedNormalizedString, stringer)
		}
	}
	return stringer()
}

func (seg *addressSegmentInternal) ToHexString(with0xPrefix bool) (string, IncompatibleAddressException) {
	var stringer func() string
	if with0xPrefix {
		stringer = func() string {
			return seg.toString(hexParamsSeg)
		}
	} else {
		stringer = func() string {
			return seg.toString(macCompressedParams)
		}
	}
	if seg.divisionValues != nil {
		if cache := seg.getCache(); cache != nil {
			if with0xPrefix {
				return cacheStr(&cache.cached0xHexString, stringer), nil
			}
			return cacheStr(&cache.cachedHexString, stringer), nil
		}
	}
	return stringer(), nil
}

type AddressSegment struct {
	addressSegmentInternal
}

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

func (seg *AddressSegment) Iterator() SegmentIterator {
	return seg.iterator()
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

func (seg *AddressSegment) ToAddressSegment() *AddressSegment {
	return seg
}

func segsSame(onePref, twoPref PrefixLen, oneVal, twoVal, oneUpperVal, twoUpperVal SegInt) bool {
	return PrefixEquals(onePref, twoPref) &&
		oneVal == twoVal && oneUpperVal == twoUpperVal
}

func segValsSame(oneVal, twoVal, oneUpperVal, twoUpperVal SegInt) bool {
	return oneVal == twoVal && oneUpperVal == twoUpperVal
}

func getPrefixValueCount(segment *AddressSegment, segmentPrefixLength BitCount) SegIntCount {
	shiftAdjustment := segment.GetBitCount() - segmentPrefixLength
	return SegIntCount(segment.GetUpperSegmentValue()>>shiftAdjustment) - SegIntCount(segment.GetSegmentValue()>>shiftAdjustment) + 1
}
