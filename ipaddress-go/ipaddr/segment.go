package ipaddr

import (
	"math/big"
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
					vals,
				},
			},
		},
	}
}

type addressSegmentInternal struct {
	addressDivisionInternal
}

func (seg *addressSegmentInternal) sameTypeContains(otherSeg *AddressSegment) bool {
	return otherSeg.GetSegmentValue() >= seg.GetSegmentValue() &&
		otherSeg.GetUpperSegmentValue() <= seg.GetUpperSegmentValue()
}

func (seg *addressSegmentInternal) Contains(other AddressSegmentType) (res bool) {
	if matchesStructure, _ := seg.matchesStructure(other); matchesStructure {
		otherSeg := other.ToAddressSegment()
		return seg.sameTypeContains(otherSeg)
	}
	return
}

func (seg *addressSegmentInternal) equalsSegment(other *AddressSegment) bool {
	matchesStructure, _ := seg.matchesStructure(other)
	return matchesStructure && seg.sameTypeEquals(other)
}

func (seg *addressSegmentInternal) sameTypeEquals(other *AddressSegment) bool {
	if seg.IsMultiple() {
		return other.IsMultiple() && segValsSame(seg.getSegmentValue(), other.getSegmentValue(),
			seg.getUpperSegmentValue(), other.getUpperSegmentValue())
	}
	return !other.IsMultiple() && seg.getSegmentValue() == other.getSegmentValue()
}

// PrefixContains returns whether the given prefix range of values contain those of the given segment.
func (seg *addressSegmentInternal) PrefixContains(other AddressSegmentType, prefixLength BitCount) bool {
	prefixLength = checkBitCount(prefixLength, seg.GetBitCount())
	shift := seg.GetBitCount() - prefixLength
	if shift <= 0 {
		return seg.Contains(other)
	}
	return (other.GetSegmentValue()>>uint(shift)) >= (seg.GetSegmentValue()>>uint(shift)) &&
		(other.GetUpperSegmentValue()>>uint(shift)) <= (seg.GetUpperSegmentValue()>>uint(shift))
}

// PrefixEquals returns whether the given prefix bits match the same bits of the given segment.
func (seg *addressSegmentInternal) PrefixEquals(other AddressSegmentType, prefixLength BitCount) bool {
	prefixLength = checkBitCount(prefixLength, seg.GetBitCount())
	shift := seg.GetBitCount() - prefixLength
	if shift <= 0 {
		return seg.GetSegmentValue() == other.GetSegmentValue() && seg.GetUpperSegmentValue() == other.GetUpperSegmentValue()
	}
	return (other.GetSegmentValue()>>uint(shift)) == (seg.GetSegmentValue()>>uint(shift)) &&
		(other.GetUpperSegmentValue()>>uint(shift)) == (seg.GetUpperSegmentValue()>>uint(shift))
}

func (seg *addressSegmentInternal) toAddressSegment() *AddressSegment {
	return (*AddressSegment)(unsafe.Pointer(seg))
}

func (seg *addressSegmentInternal) ToAddressDivision() *AddressDivision {
	return (*AddressDivision)(seg)
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

func (seg *addressSegmentInternal) Matches(value SegInt) bool {
	return seg.matches(DivInt(value))
}

func (seg *addressSegmentInternal) MatchesWithMask(value, mask SegInt) bool {
	return seg.matchesWithMask(DivInt(value), DivInt(mask))
}

func (seg *addressSegmentInternal) MatchesValsWithMask(lowerValue, upperValue, mask SegInt) bool {
	return seg.matchesValsWithMask(DivInt(lowerValue), DivInt(upperValue), DivInt(mask))
}

func (seg *addressSegmentInternal) GetPrefixCountLen(segmentPrefixLength BitCount) *big.Int {
	return bigZero().SetUint64(seg.GetPrefixValueCount(segmentPrefixLength))
}

func (seg *addressSegmentInternal) GetPrefixValueCount(segmentPrefixLength BitCount) SegIntCount {
	return getPrefixValueCount(seg.toAddressSegment(), segmentPrefixLength)
}

func (seg *addressSegmentInternal) GetValueCount() SegIntCount {
	return uint64(seg.GetUpperSegmentValue()-seg.GetSegmentValue()) + 1
}

func (seg *addressSegmentInternal) GetMaxValue() SegInt {
	return ^(^SegInt(0) << uint(seg.GetBitCount()))
}

// TestBit computes (this & (1 << n)) != 0), using the lower value of this segment.
func (div *addressSegmentInternal) TestBit(n BitCount) bool {
	value := div.GetSegmentValue()
	return (value & (1 << uint(n))) != 0
}

// Returns true if the bit in the lower value of this segment at the given index is 1, where index 0 is the most significant bit.
func (div *addressSegmentInternal) IsOneBit(segmentBitIndex BitCount) bool {
	value := div.GetSegmentValue()
	bitCount := div.GetBitCount()
	return (value & (1 << uint(bitCount-(segmentBitIndex+1)))) != 0
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

func (seg *addressSegmentInternal) withoutPrefixLen() *AddressSegment {
	if seg.isPrefixed() {
		vals := seg.deriveNewMultiSeg(seg.GetSegmentValue(), seg.GetUpperSegmentValue(), nil)
		return createAddressDivision(vals).ToAddressSegment()
	}
	return seg.toAddressSegment()
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

//func (seg *addressSegmentInternal) GetSegmentNetworkMask(networkBits BitCount) SegInt {
//	bc := seg.GetBitCount()
//	networkBits = checkBitCount(networkBits, bc)
//	return seg.GetMaxValue() & (^SegInt(0) << uint(bc-networkBits))
//}
//
//func (seg *addressSegmentInternal) GetSegmentHostMask(networkBits BitCount) SegInt {
//	bc := seg.GetBitCount()
//	networkBits = checkBitCount(networkBits, bc)
//	return ^(^SegInt(0) << uint(bc-networkBits))
//}

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

func (seg *addressSegmentInternal) ToHexString(with0xPrefix bool) (string, IncompatibleAddressError) {
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

func (seg *addressSegmentInternal) reverseMultiValSeg(perByte bool) (res *AddressSegment, err IncompatibleAddressError) {
	if isReversible := seg.isReversibleRange(perByte); isReversible {
		// all reversible multi-valued segs reverse to the same segment
		if seg.isPrefixed() {
			res = createAddressSegment(seg.deriveNewMultiSeg(seg.GetSegmentValue(), seg.GetUpperSegmentValue(), nil))
			return
		}
		res = seg.toAddressSegment()
		return
	}
	err = &incompatibleAddressError{addressError{key: "ipaddress.error.reverseRange"}}
	return
}

func (seg *addressSegmentInternal) ReverseBits(perByte bool) (res *AddressSegment, err IncompatibleAddressError) {
	if seg.divisionValues == nil {
		res = seg.toAddressSegment()
		return
	}
	if seg.IsMultiple() {
		return seg.reverseMultiValSeg(perByte)
	}
	byteCount := seg.GetByteCount()
	oldVal := seg.GetSegmentValue()
	var val SegInt
	switch byteCount {
	case 1:
		val = SegInt(reverseUint8(uint8(oldVal)))
	case 2:
		val = SegInt(reverseUint16(uint16(oldVal)))
		if perByte {
			val = ((val & 0xff) << 8) | (val >> 8)
		}
	case 3:
		val = reverseUint32(uint32(oldVal)) >> 8
		if perByte {
			val = ((val & 0xff) << 16) | (val & 0xff00) | (val >> 16)
		}
	case 4:
		val = reverseUint32(uint32(oldVal))
		if perByte {
			val = ((val & 0xff) << 24) | (val&0xff00)<<8 | (val&0xff0000)>>8 | (val >> 24)
		}
	default: // SegInt is at most 32 bits so this default case is not possible
		err = &incompatibleAddressError{addressError{key: "ipaddress.error.reverseRange"}}
		return
	}
	if oldVal == val && !seg.isPrefixed() {
		res = seg.toAddressSegment()
	} else {
		res = createAddressSegment(seg.deriveNewSeg(val, nil))
	}
	return
}

func (seg *addressSegmentInternal) ReverseBytes() (res *AddressSegment, err IncompatibleAddressError) {
	byteCount := seg.GetByteCount()
	if byteCount <= 1 {
		res = seg.toAddressSegment()
		return
	}
	if seg.IsMultiple() {
		return seg.reverseMultiValSeg(false)
	}
	oldVal := seg.GetSegmentValue()
	var val SegInt
	switch byteCount {
	case 2:
		val = ((oldVal & 0xff) << 8) | (oldVal >> 8)
	case 3:
		val = ((oldVal & 0xff) << 16) | (oldVal & 0xff00) | (oldVal >> 16)
	case 4:
		val = ((oldVal & 0xff) << 24) | (oldVal&0xff00)<<8 | (oldVal&0xff0000)>>8 | (oldVal >> 24)
	default: // SegInt is at most 32 bits so this default case is not possible
		err = &incompatibleAddressError{addressError{key: "ipaddress.error.reverseRange"}}
		return
	}
	if oldVal == val && !seg.isPrefixed() {
		res = seg.toAddressSegment()
	} else {
		res = createAddressSegment(seg.deriveNewSeg(val, nil))
	}
	return
}

func (seg *addressSegmentInternal) isReversibleRange(perByte bool) (isReversible bool) {
	// Consider the case of reversing the bits of a range
	// Any range that can be successfully reversed must span all bits (otherwise after flipping you'd have a range in which the lower bit is constant, which is impossible in any contiguous range)
	// So that means at least one value has 0xxxx and another has 1xxxx (using 5 bits for our example). This means you must have the values 01111 and 10000 since the range is contiguous.
	// But reversing a range twice results in the original again, meaning the reversed must also be reversible, so the reversed also has 01111 and 10000.
	// So this means both the original and the reversed also have those two patterns flipped, which are 00001 and 11110.
	// So this means both ranges must span from at most 1 to at least 11110.
	// However, the two remaining values, 0 and 11111, are optional, as they are boundary value and remain themselves when reversed, and hence have no effect on whether the reversed range is contiguous.
	// So the only reversible ranges are 0-11111, 0-11110, 1-11110, and 1-11111.

	//-----------------------
	// Consider the case of reversing each of the bytes of a range.
	//
	// You can apply the same argument to the top multiple byte,
	// which means it is 0 or 1 to 254 or 255.
	// Suppose there is another byte to follow.
	// If you take the upper byte range, and you hold it constant, then reversing the next byte applies the same argument to that byte.
	// And so the lower byte must span from at most 1 to at least 11111110.
	// This argument holds when holding the upper byte constant at any value.
	// So the lower byte must span from at most 1 to at least 111111110 for any value.
	// So you have x 00000001-x 111111110 and y 00000001-y 111111110 and so on.

	// But all the bytes form a range, so you must also have the values in-between.
	// So that means you have 1 00000001 to 1 111111110 to 10 111111110 to 11 111111110 all the way to x 11111110, where x is at least 11111110.
	// In all cases, the upper byte lower value is at most 1, and 1 < 10000000.
	// That means you always have 10000000 00000000.
	// So you have the reverse as well (as argued above, for any value we also have the reverse).
	// So you always have 00000001 00000000.
	//
	// In other words, if the upper byte has lower 0, then the full bytes lower must be at most 0 00000001
	// Otherwise, when the upper byte has lower 1, the the full bytes lower is at most 1 00000000.
	//
	// In other words, if any upper byte has lower value 1, then all lower values to follow are 0.
	// If all upper bytes have lower value 0, then the next byte is permitted to have lower value 1.
	//
	// In summary, any upper byte having lower of 1 forces the remaining lower values to be 0.
	//
	// WHen the upper bytes are all zero, and thus the lower is at most 0 0 0 0 1,
	// then the only remaining lower value is 0 0 0 0 0.  This reverses to itself, so it is optional.
	//
	// The same argument applies to upper boundaries.
	//

	//-----------------------
	// Consider the case of reversing the bytes of a range.
	// Any range that can be successfully reversed must span all bits
	// (otherwise after flipping you'd have a range in which a lower bit is constant, which is impossible in any contiguous range)
	// So that means at least one value has 0xxxxx and another has 1xxxxx (we use 6 bits for our example, and we assume each byte has 3 bits).
	// This means you must have the values 011111 and 100000 since the range is contiguous.
	// But reversing a range twice results in the original again, meaning the reversed must also be reversible, so the reversed also has 011111 and 100000.

	// So this means both the original and the reversed also have those two bytes in each flipped, which are 111011 and 000100.
	// So the range must have 000100, 011111, 100000, 111011, so it must be at least 000100 to 111011.
	// So what if the range does not have 000001?  then the reversed range cannot have 001000, the byte-reversed address.
	// But we know it spans 000100 to 111011. So the original must have 000001.
	// What if it does not have 111110?  Then the reversed cannot have 110111, the byte-reversed address.
	// But we know it ranges from 000100 to 111011.  So the original must have 111110.
	// So it must range from 000001 to 111110.  The only remaining values in question are 000000 and 111111.
	// But once again, the two remaining values are optional, because the byte-reverse to themselves.
	// So for the byte-reverse case, we have the same potential ranges as in the bit-reverse case: 0-111111, 0-111110, 1-111110, and 1-111111
	if perByte {
		byteCount := seg.GetByteCount()
		bitCount := seg.GetBitCount()
		val := seg.GetSegmentValue()
		upperVal := seg.GetUpperSegmentValue()
		for i := 1; i <= byteCount; i++ {
			bitShift := i << 3
			shift := (bitCount - BitCount(bitShift))
			byteVal := 0xff & (val >> uint(shift))
			upperByteVal := 0xff & (upperVal >> uint(shift))
			if byteVal != upperByteVal {
				if byteVal > 1 || upperByteVal < 254 {
					return false
				}
				i++
				if i <= byteCount {
					lowerIsZero := byteVal == 1
					upperIsMax := upperByteVal == 254
					for {
						bitShift = i << 3
						shift = bitCount - BitCount(bitShift)
						byteVal = 0xff & (val >> uint(shift))
						upperByteVal = 0xff & (upperVal >> uint(shift))
						if lowerIsZero {
							if byteVal != 0 {
								return
							}
						} else {
							if byteVal > 1 {
								return
							}
							lowerIsZero = byteVal == 1
						}
						if upperIsMax {
							if upperByteVal != 255 {
								return
							}
						} else {
							if upperByteVal < 254 {
								return
							}
							upperIsMax = upperByteVal == 254
						}
						i++
						if i > byteCount {
							break
						}
					}
				}
				return true
			}
		}
		return true
	}
	isReversible = seg.GetSegmentValue() <= 1 && seg.GetUpperSegmentValue() >= seg.GetMaxValue()-1
	return
}

//

type AddressSegment struct {
	addressSegmentInternal
}

//func (seg *AddressSegment) Equals(other DivisionType) bool {
//	if seg == nil {
//		return seg.getAddrType() == zeroType && other.(StandardDivisionType).ToAddressDivision() == nil
//	}
//	return seg.equals(other)
//}
//
//func (seg *AddressSegment) CompareTo(item AddressItem) int {
//	return CountComparator.Compare(seg, item)
//}

func (seg *AddressSegment) IsIPAddressSegment() bool {
	return seg != nil && seg.matchesIPSegment()
}

func (seg *AddressSegment) IsIPv4AddressSegment() bool {
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
	return SegIntCount(segment.GetUpperSegmentValue()>>uint(shiftAdjustment)) - SegIntCount(segment.GetSegmentValue()>>uint(shiftAdjustment)) + 1
}
