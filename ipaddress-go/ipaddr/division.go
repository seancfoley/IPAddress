package ipaddr

import (
	"fmt"
	"math/big"
	"math/bits"
	"sync"
	"unsafe"
)

// DivInt is an integer type for holding generic division values, which can be larger than segment values
type DivInt = uint64

const DivIntSize = 64

type divisionValuesBase interface { // shared by standard and large divisions
	getBitCount() BitCount

	getByteCount() int

	// getValue gets the lower value for a large division
	getValue() *big.Int

	// getValue gets the upper value for a large division
	getUpperValue() *big.Int

	includesZero() bool

	includesMax() bool

	isMultiple() bool

	getCount() *big.Int

	// convert lower and upper values to byte arrays
	calcBytesInternal() (bytes, upperBytes []byte)

	// getCache returns a cache for those divisions which cache their values, or nil otherwise
	getCache() *divCache

	getAddrType() addrType
}

type deriver interface {
	// deriveNew produces a new segment with the same bit count as the old
	deriveNewMultiSeg(val, upperVal SegInt, prefLen PrefixLen) divisionValues

	// deriveNew produces a new segment with the same bit count as the old
	deriveNewSeg(val SegInt, prefLen PrefixLen) divisionValues
}

// DivisionValues represents divisions with values that are 64 bits or less
type divisionValues interface {
	divisionValuesBase

	// getDivisionPrefixLength provides the prefix length
	// if is aligned is true and the prefix is non-nil, any divisions that follow in the same grouping have a zero-length prefix
	getDivisionPrefixLength() PrefixLen

	// getDivisionValue gets the lower value for a division
	getDivisionValue() DivInt

	// getUpperDivisionValue gets the upper value for a division
	getUpperDivisionValue() DivInt

	// deriveNew produces a new division with the same bit count as the old
	deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues

	// getSegmentValue gets the lower value for a segment
	getSegmentValue() SegInt

	// getUpperSegmentValue gets the upper value for a segment
	getUpperSegmentValue() SegInt

	deriver
}

//TODO your generic addressDivision calcBytesInternal (which will work with uint64) will look like this
//func (div *addressDivisionInternal) calcBytesInternal() (bytes, upperBytes []byte) {
//	isMultiple := div.IsMultiple()
//	byteCount := div.getByteCount()
//	bytes = make([]byte, byteCount)
//	val := div.getDivisionValue()
//	var upperVal DivInt
//	if isMultiple {
//		upperBytes = make([]byte, byteCount)
//		upperVal = div.getUpperDivisionValue()
//	} else {
//		upperBytes = bytes
//	}
//	bitCount := div.getBitCount()
//	byteIndex := byteCount - 1
//	for {
//		bytes[byteIndex] |= byte(val)
//		val >>= 8
//		if isMultiple {
//			upperBytes[byteIndex] = byte(upperVal)
//			upperVal >>= 8
//		}
//		if bitCount <= 8 {
//			return
//		}
//		bitCount -= 8
//		byteIndex--
//	}
//}

type divCache struct {
	cacheLock sync.RWMutex

	lowerBytes, upperBytes             []byte
	cachedString, cachedWildcardString string
	isSinglePrefixBlock                boolSetting //TODO maybe init this on creation or put it in divisionValues or just calculate it, maybe do the same in Java
}

//TODO everything must become a Stringer, following the pattern of toString() in Java

func createAddressDivision(vals divisionValues) *AddressDivision {
	return &AddressDivision{addressDivisionInternal{addressDivisionBase{divisionValues: vals}}}
}

type addressDivisionInternal struct {
	addressDivisionBase
}

func (div *addressDivisionInternal) getAddrType() addrType {
	if div.divisionValues == nil {
		return zeroType
	}
	return div.divisionValues.getAddrType()
}

func (div *addressDivisionInternal) String() string {
	if div.IsMultiple() {
		return fmt.Sprintf("%x-%x", div.GetDivisionValue(), div.GetUpperDivisionValue())
	}
	return fmt.Sprintf("%x", div.GetDivisionValue())
	/*
			We will have  default radix, which starts as hex, but when we switch to ipv4 section and gain ipv4 addr type,
			each division will have default radix reset to 10
			but that will require locking so the default radix will be part of the cache and use the cache lock

			The downside is this means that this would mean that the result of this method can change after conversion to ipv4 and back again

			So maybe you don't want to do that

			If you do not, then maybe you want to change the java side too to always use hex by default, even for IPv4?
			Well, that remains to be seen, because the way strings work is a bit different
			IPv4Segment instances override the parent behaviour.  So it's not the same, and only applies to IPAddressBitsDivision.

			So no I am thinking, no switcheroo, just stick to hex

		TODO now we've added addrType to divisions, that settles it.  We need to check addrType and scale up
		given the address type, otherwise use hex.  In fact, could just stick to hex and scale up for ipv4 only.

				@Override
				public String toString() {
					int radix = getDefaultTextualRadix();
					IPStringOptions opts;
					switch(radix) {
					case 8:
						opts = OCTAL_PARAMS;
						break;
					case 16:
						opts = HEX_PARAMS;
						break;
					case 10:
						opts = DECIMAL_PARAMS;
						break;
					default:
						opts = new IPStringOptions.Builder(radix).setWildcards(new Wildcards(IPAddress.RANGE_SEPARATOR_STR)).toOptions();
						break;
					}
					StringBuilder builder = new StringBuilder(34);
					toParams(opts).appendSingleDivision(this, builder);
					return builder.toString();
				}


	*/
}

func (div *addressDivisionInternal) isPrefixed() bool {
	return div.getDivisionPrefixLength() != nil
}

// return whether the division range includes the block of values for the given prefix length
func (div *addressDivisionInternal) containsPrefixBlock(divisionPrefixLen BitCount) bool {
	return div.isPrefixBlockVals(div.GetDivisionValue(), div.GetUpperDivisionValue(), divisionPrefixLen)
}

// Returns whether the division range includes the block of values for its prefix length
func (div *addressDivisionInternal) isPrefixBlockVals(divisionValue, upperValue DivInt, divisionPrefixLen BitCount) bool {
	if divisionPrefixLen <= 0 {
		return divisionValue == 0 && upperValue == div.getMaxValue()
	}
	bitCount := div.GetBitCount()
	if divisionPrefixLen >= bitCount {
		return true
	}
	var ones = ^DivInt(0)
	var divisionBitMask DivInt = ^(ones << bitCount)
	var divisionPrefixMask DivInt = ones << (bitCount - divisionPrefixLen)
	var divisionNonPrefixMask = ^divisionPrefixMask
	return testRange(divisionValue,
		upperValue,
		upperValue,
		divisionPrefixMask&divisionBitMask,
		divisionNonPrefixMask)
}

// Returns whether the given range of segmentValue to upperValue is equivalent to the range of segmentValue with the prefix of divisionPrefixLen
func (div *addressDivisionInternal) isSinglePrefixBlock(divisionValue, upperValue DivInt, divisionPrefixLen BitCount) bool {
	if divisionPrefixLen == 0 {
		return divisionValue == 0 && upperValue == div.getMaxValue()
	}
	bitCount := div.GetBitCount()
	var ones = ^DivInt(0)
	var divisionBitMask DivInt = ^(ones << bitCount)
	var divisionPrefixMask DivInt = ones << (bitCount - divisionPrefixLen)
	var divisionNonPrefixMask = ^divisionPrefixMask
	return testRange(divisionValue,
		divisionValue,
		upperValue,
		divisionPrefixMask&divisionBitMask,
		divisionNonPrefixMask)
}

func (div *addressDivisionInternal) ContainsPrefixBlock(prefixLen BitCount) bool {
	return div.isPrefixBlockVals(div.GetDivisionValue(), div.GetUpperDivisionValue(), prefixLen)
}

func (div *addressDivisionInternal) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	return div.isSinglePrefixBlock(div.GetDivisionValue(), div.GetUpperDivisionValue(), prefixLen)
}

func (div *addressDivisionInternal) GetMinPrefixLengthForBlock() BitCount {
	result := div.GetBitCount()
	if !div.IsMultiple() {
		return result
	} else if div.IsFullRange() {
		return 0
	}
	lowerZeros := bits.TrailingZeros64(uint64(div.getDivisionValue()))
	if lowerZeros != 0 {
		upperOnes := bits.TrailingZeros64(^div.getUpperDivisionValue())
		if upperOnes != 0 {
			var prefixedBitCount int
			if lowerZeros < upperOnes {
				prefixedBitCount = lowerZeros
			} else {
				prefixedBitCount = upperOnes
			}
			result -= BitCount(prefixedBitCount)
		}
	}
	return result
}

func (div *addressDivisionInternal) GetPrefixLengthForSingleBlock() PrefixLen {
	divPrefix := div.GetMinPrefixLengthForBlock()
	lowerValue := div.GetDivisionValue()
	upperValue := div.GetUpperDivisionValue()
	bitCount := div.GetBitCount()
	if divPrefix == bitCount {
		if lowerValue == upperValue {
			return cache(divPrefix)
		}
	} else {
		shift := bitCount - divPrefix
		if lowerValue>>shift == upperValue>>shift {
			return cache(divPrefix)
		}
	}
	return nil
}

// return whether the division range includes the block of values for the division prefix length,
// or false if the division has no prefix length
func (div *addressDivisionInternal) isPrefixBlock() bool {
	prefLen := div.getDivisionPrefixLength()
	return prefLen != nil && div.containsPrefixBlock(*prefLen)
}

func (div *addressDivisionInternal) getMaxValue() DivInt {
	return ^(^DivInt(0) << div.GetBitCount())
}

func (div *addressDivisionInternal) GetDivisionValue() DivInt {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.getDivisionValue()
}

func (div *addressDivisionInternal) GetUpperDivisionValue() DivInt {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.getUpperDivisionValue()
}

func (div *addressDivisionInternal) toPrefixedNetworkDivision(divPrefixLength PrefixLen) *AddressDivision {
	return div.toNetworkDivision(divPrefixLength, true)
}

func (div *addressDivisionInternal) toNetworkDivision(divPrefixLength PrefixLen, withPrefixLength bool) *AddressDivision {
	vals := div.divisionValues
	if vals == nil {
		return div.toAddressDivision()
	}
	lower := div.GetDivisionValue()
	upper := div.GetUpperDivisionValue()
	var newLower, newUpper DivInt
	hasPrefLen := divPrefixLength != nil
	if hasPrefLen {
		prefBits := *divPrefixLength
		bitCount := div.GetBitCount()
		if prefBits < 0 {
			prefBits = 0
		} else if prefBits > bitCount {
			prefBits = bitCount
		}
		mask := ^DivInt(0) << (bitCount - prefBits)
		newLower = lower & mask
		newUpper = upper | ^mask
		if !withPrefixLength {
			divPrefixLength = nil
		}
		if divsSame(divPrefixLength, div.getDivisionPrefixLength(), newLower, lower, newUpper, upper) {
			return div.toAddressDivision()
		}
	} else {
		withPrefixLength = false
		divPrefixLength = nil
		if div.getDivisionPrefixLength() == nil {
			return div.toAddressDivision()
		}
	}
	newVals := div.deriveNew(newLower, newUpper, divPrefixLength)
	return createAddressDivision(newVals)
}

func (div *addressDivisionInternal) toPrefixedDivision(divPrefixLength PrefixLen) *AddressDivision {
	hasPrefLen := divPrefixLength != nil
	bitCount := div.GetBitCount()
	if hasPrefLen {
		prefBits := *divPrefixLength
		if prefBits < 0 {
			prefBits = 0
		} else if prefBits > bitCount {
			prefBits = bitCount
		}
		if div.isPrefixed() && prefBits == *div.getDivisionPrefixLength() {
			return div.toAddressDivision()
		}
	} else {
		return div.toAddressDivision()
	}
	lower := div.GetDivisionValue()
	upper := div.GetUpperDivisionValue()
	newVals := div.deriveNew(lower, upper, divPrefixLength)
	return createAddressDivision(newVals)
}

func (div *addressDivisionInternal) GetCount() *big.Int {
	if !div.IsMultiple() {
		return bigOne()
	}
	if div.IsFullRange() {
		res := bigZero()
		return res.SetUint64(0xffffffffffffffff).Add(res, bigOneConst())
	}
	return bigZero().SetUint64((div.getUpperDivisionValue() - div.getDivisionValue()) + 1)
}

func (div *addressDivisionInternal) Equals(other AddressGenericDivision) bool {
	// TODO an identity/pointer comparison which requires we grab the *addressDivisionInternal or *addressDivisionBase from AddressGenericDivision
	if otherDiv, ok := other.(AddressStandardDivision); ok {
		if div.IsMultiple() {
			if other.IsMultiple() {
				matches, _ := div.matchesStructure(other)
				return matches && divValsSame(div.GetDivisionValue(), otherDiv.GetDivisionValue(),
					div.GetUpperDivisionValue(), otherDiv.GetUpperDivisionValue())
			} else {
				return false
			}
		} else if other.IsMultiple() {
			return false
		} else {
			matches, _ := div.matchesStructure(other)
			return matches && divValSame(div.GetDivisionValue(), otherDiv.GetDivisionValue())
		}
	}
	return div.addressDivisionBase.Equals(other)
}

func (div *addressDivisionInternal) matchesIPSegment() bool {
	return div.divisionValues == nil || div.getAddrType().isIP()
}

func (div *addressDivisionInternal) matchesIPv4Segment() bool {
	return div.divisionValues != nil && div.getAddrType().isIPv4()
}

func (div *addressDivisionInternal) matchesIPv6Segment() bool {
	return div.divisionValues != nil && div.getAddrType().isIPv6()
}

func (div *addressDivisionInternal) matchesMACSegment() bool {
	return div.divisionValues != nil && div.getAddrType().isMAC()
}

func (div *addressDivisionInternal) matchesSegment() bool {
	return div.GetBitCount() <= SegIntSize
}

func (div *addressDivisionInternal) toAddressDivision() *AddressDivision {
	return (*AddressDivision)(unsafe.Pointer(div))
}

func (div *addressDivisionInternal) toAddressSegment() *AddressSegment {
	if div.matchesSegment() {
		return (*AddressSegment)(unsafe.Pointer(div))
	}
	return nil
}

type AddressDivision struct {
	addressDivisionInternal
}

// Note: many of the methods below are not public to addressDivisionInternal because segments have corresponding methods using segment values
//func (div *AddressDivision) GetDivisionValue() DivInt {
//	return div.getDivisionValue()
//}
//
//func (div *AddressDivision) GetUpperDivisionValue() DivInt {
//	return div.getUpperDivisionValue()
//}

func (div *AddressDivision) GetMaxValue() DivInt {
	return div.getMaxValue()
}

func (div *AddressDivision) IsAddressSegment() bool {
	return div != nil && div.matchesSegment()
}

func (div *AddressDivision) IsIPAddressSegment() bool {
	return div != nil && div.matchesIPSegment()
}

func (div *AddressDivision) IsIPv4AddressSegment() bool {
	return div != nil && div.matchesIPv4Segment()
}

func (div *AddressDivision) IsIPv6AddressSegment() bool {
	return div != nil && div.matchesIPv6Segment()
}

func (div *AddressDivision) IsMACAddressSegment() bool {
	return div != nil && div.matchesMACSegment()
}

func (div *AddressDivision) ToIPAddressSegment() *IPAddressSegment {
	if div.IsIPAddressSegment() {
		return (*IPAddressSegment)(unsafe.Pointer(div))
	}
	return nil
}

func (div *AddressDivision) ToIPv4AddressSegment() *IPv4AddressSegment {
	if div.IsIPv4AddressSegment() {
		return (*IPv4AddressSegment)(unsafe.Pointer(div))
	}
	return nil
}

func (div *AddressDivision) ToIPv6AddressSegment() *IPv6AddressSegment {
	if div.IsIPv6AddressSegment() {
		return (*IPv6AddressSegment)(unsafe.Pointer(div))
	}
	return nil
}

func (div *AddressDivision) ToMACAddressSegment() *MACAddressSegment {
	if div.IsMACAddressSegment() {
		return (*MACAddressSegment)(unsafe.Pointer(div))
	}
	return nil
}

func (div *AddressDivision) ToAddressSegment() *AddressSegment {
	if div.IsAddressSegment() {
		return (*AddressSegment)(unsafe.Pointer(div))
	}
	return nil
}

func (div *AddressDivision) ToAddressDivision() *AddressDivision {
	return div
}

func testRange(lowerValue, upperValue, finalUpperValue, networkMask, hostMask DivInt) bool {
	return lowerValue == (lowerValue&networkMask) && finalUpperValue == (upperValue|hostMask)
}

func divsSame(onePref, twoPref PrefixLen, oneVal, twoVal, oneUpperVal, twoUpperVal DivInt) bool {
	//return onePref.Equals(twoPref) &&
	return PrefixEquals(onePref, twoPref) &&
		oneVal == twoVal && oneUpperVal == twoUpperVal
}

func divValsSame(oneVal, twoVal, oneUpperVal, twoUpperVal DivInt) bool {
	return oneVal == twoVal && oneUpperVal == twoUpperVal
}

func divValSame(oneVal, twoVal DivInt) bool {
	return oneVal == twoVal
}
