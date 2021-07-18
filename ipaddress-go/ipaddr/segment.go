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

func (seg *addressSegmentInternal) Contains(other AddressSegmentType) (res bool) {
	if matchesStructure, _ := seg.matchesStructure(other); matchesStructure {
		otherSeg := other.ToAddressSegment()
		res = otherSeg.GetSegmentValue() >= seg.GetSegmentValue() &&
			otherSeg.GetUpperSegmentValue() <= seg.GetUpperSegmentValue()
	}
	return
}

func (seg *addressSegmentInternal) EqualsSegment(other *AddressSegment) bool {
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
	return ^(^SegInt(0) << seg.GetBitCount())
}

// TestBit computes (this & (1 << n)) != 0), using the lower value of this segment.
func (div *addressSegmentInternal) TestBit(n BitCount) bool {
	value := div.GetSegmentValue()
	return (value & (1 << n)) != 0
}

// Returns true if the bit in the lower value of this segment at the given index is 1, where index 0 is the most significant bit.
func (div *addressSegmentInternal) IsOneBit(segmentBitIndex BitCount) bool {
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
	if isReversible, multiValueByteIndex := seg.isReversibleRange(perByte); isReversible {
		if perByte {
			var result, upperResult SegInt
			byteCount := seg.GetByteCount()
			bitCount := seg.GetBitCount()
			val := seg.GetSegmentValue()
			upperVal := seg.GetUpperSegmentValue()
			for i := 1; i <= byteCount; i++ {
				result = result << 8
				bytes := BitCount(i << 3)
				b := val >> (bitCount - bytes)
				if i <= multiValueByteIndex {
					result |= SegInt(reverseUint8(uint8(b)))
					upperResult = result
				} else {
					ub := upperVal >> (bitCount - bytes)
					result |= b
					upperResult |= ub
				}
			}
			if val == result && upperVal == upperResult && !seg.isPrefixed() {
				res = seg.toAddressSegment()
			} else {
				res = createAddressSegment(seg.deriveNewMultiSeg(result, upperResult, nil))
			}
		} else {
			if seg.isPrefixed() {
				res = createAddressSegment(seg.deriveNewMultiSeg(seg.GetSegmentValue(), seg.GetUpperSegmentValue(), nil))
				return
			}
			res = seg.toAddressSegment()
		}
		return
	}
	err = &incompatibleAddressError{addressError{str: seg.String(), key: "ipaddress.error.reverseRange"}}
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
		err = &incompatibleAddressError{addressError{str: seg.String(), key: "ipaddress.error.reverseRange"}}
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
		err = &incompatibleAddressError{addressError{str: seg.String(), key: "ipaddress.error.reverseRange"}}
		return
	}
	if oldVal == val && !seg.isPrefixed() {
		res = seg.toAddressSegment()
	} else {
		res = createAddressSegment(seg.deriveNewSeg(val, nil))
	}
	return
}

func (seg *addressSegmentInternal) isReversibleRange(perByte bool) (isReversible bool, multiValueByteIndex int) {
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
	// If you apply the same argument to the top (multiple) byte, that any top byte value must result in a new range with that top byte reversed,
	// you have the only possible ranges in the top byte are: 0-11111, 0-11110, 1-11110, and 1-11111.
	// Any one of those ranges means that all possible values are in the bottom bytes.
	// So you end up with a similar result.  Whether 0 or 11111 are included in the top byte is optional.
	// And if each one is included, it reverses to itself, the rest of the range staying the same, and thus the whole range stays the same in that one byte.
	// That first range byte reverses to itself.  The bottom bytes are full-range and thus reverse to themselves.
	// The single-valued bytes before that first range byte have their single value reversed.

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
		// needs to be 0 0 range fullrange fullrange
		// where range is 0 or 1 to 254 or 255
		// otherwise, not reversible per byte
		byteCount := seg.GetByteCount()
		bitCount := seg.GetBitCount()
		val := seg.GetSegmentValue()
		upperVal := seg.GetUpperSegmentValue()
	top:
		for i := 1; i <= byteCount; i++ {
			bitShift := i << 3
			shift := (bitCount - BitCount(bitShift))
			byteVal := 0xff & (val >> shift)
			upperByteVal := 0xff & (upperVal >> shift)
			if byteVal != upperByteVal {
				multiValueByteIndex = i - 1
				if byteVal <= 1 && upperByteVal >= 254 {
					for i++; i <= byteCount; i++ {
						bitShift = i << 3
						shift = (bitCount - BitCount(bitShift))
						byteVal = 0xff & (val >> shift)
						upperByteVal = 0xff & (upperVal >> shift)
						if byteVal > 0 || upperByteVal < 255 {
							break top
						}
					}
					isReversible = true
					return
				}
				break
			}
		}
		return
	}
	isReversible = seg.GetSegmentValue() <= 1 && seg.GetUpperSegmentValue() >= seg.GetMaxValue()-1
	return
}

//

type AddressSegment struct {
	addressSegmentInternal
}

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
	return SegIntCount(segment.GetUpperSegmentValue()>>shiftAdjustment) - SegIntCount(segment.GetSegmentValue()>>shiftAdjustment) + 1
}
