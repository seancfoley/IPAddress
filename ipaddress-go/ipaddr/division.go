package ipaddr

import (
	"fmt"
	"sync"
	"unsafe"
)

// DivInt is an integer type for holding generic division values, which can be larger than segment values
type DivInt = uint64

const DivIntSize = 64

type divisionValuesBase interface { // shared by standard and large divisions
	GetBitCount() BitCount

	GetByteCount() int
}

// DivisionValues represents divisions with values that are 64 bits or less
type divisionValues interface {
	divisionValuesBase

	// getDivisionPrefixLength provides the prefix length
	// if is aligned is true and the prefix is non-nil, any divisions that follow in the same grouping have a zero-length prefix
	getDivisionPrefixLength() PrefixLen

	// getDivisionValue gets the lower value for the division
	getDivisionValue() DivInt

	// getUpperDivisionValue gets the upper value for the division
	getUpperDivisionValue() DivInt

	// deriveNew produces a new division with the same bit count as the old
	deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues

	// getSegmentValue gets the lower value truncated to a SegInt
	getSegmentValue() SegInt

	// getUpperSegmentValue gets the upper value truncated to a SegInt
	getUpperSegmentValue() SegInt

	// deriveNew produces a new division with the same bit count as the old
	deriveNewSeg(val, upperVal SegInt, prefLen PrefixLen) divisionValues

	// getCache returns a cache for this divisions which cache their values, or nil otherwise
	getCache() *divCache
}

type divCache struct {
	sync.RWMutex

	lowerBytes, upperBytes             []byte
	cachedString, cachedWildcardString string
	isSinglePrefixBlock                boolSetting //TODO init this on creation or put it in divisionValues or just calculate it, maybe do the same in Java

	// I decided it makes no sense to do this, so network will go away
	//network                            AddressNetwork // never nil // equivalent to overriding getNetwork(), ToIPvX(), IsIPvxConvertible(), etc, in Java, allows you to supply your own conversion
}

//TODO everything must become a Stringer, following the pattern of toString() in Java

func createAddressDivision(vals divisionValues) *AddressDivision {
	return &AddressDivision{addressDivisionInternal{divisionValues: vals}}
}

type addressDivisionInternal struct {
	divisionValues
}

func (div *addressDivisionInternal) String() string {
	if div.isMultiple() {
		return fmt.Sprintf("%x-%x", div.getDivisionValue(), div.getUpperDivisionValue())
	}
	return fmt.Sprintf("%x", div.getDivisionValue())
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
	return div.isPrefixBlockVals(div.getDivisionValue(), div.getUpperDivisionValue(), divisionPrefixLen)
}

// Returns whether the division range includes the block of values for its prefix length
func (div *addressDivisionInternal) isPrefixBlockVals(divisionValue, upperValue DivInt, divisionPrefixLen BitCount) bool {
	if divisionPrefixLen == 0 {
		return divisionValue == 0 && upperValue == div.GetMaxValue()
	}
	bitCount := div.GetBitCount()
	var ones DivInt = ^DivInt(0)
	var divisionBitMask DivInt = ^(ones << bitCount)
	var divisionPrefixMask DivInt = ones << (bitCount - divisionPrefixLen)
	var divisionNonPrefixMask DivInt = ^divisionPrefixMask
	return testRange(divisionValue,
		upperValue,
		upperValue,
		divisionPrefixMask&divisionBitMask,
		divisionNonPrefixMask)
}

// Returns whether the given range of segmentValue to upperValue is equivalent to the range of segmentValue with the prefix of divisionPrefixLen
func (div *addressDivisionInternal) isSinglePrefixBlock(divisionValue, upperValue DivInt, divisionPrefixLen BitCount) bool {
	if divisionPrefixLen == 0 {
		return divisionValue == 0 && upperValue == div.GetMaxValue()
	}
	bitCount := div.GetBitCount()
	var ones DivInt = ^DivInt(0)
	var divisionBitMask DivInt = ^(ones << bitCount)
	var divisionPrefixMask DivInt = ones << (bitCount - divisionPrefixLen)
	var divisionNonPrefixMask DivInt = ^divisionPrefixMask
	return testRange(divisionValue,
		divisionValue,
		upperValue,
		divisionPrefixMask&divisionBitMask,
		divisionNonPrefixMask)
}

// return whether the division range includes the block of values for the division prefix length,
// or false if the division has no prefix length
func (div *addressDivisionInternal) isPrefixBlock() bool {
	prefLen := div.getDivisionPrefixLength()
	return prefLen != nil && div.containsPrefixBlock(*prefLen)
}

func (div *addressDivisionInternal) getDivisionPrefixLength() PrefixLen {
	vals := div.divisionValues
	if vals == nil {
		return nil
	}
	return vals.getDivisionPrefixLength()
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

func (div *addressDivisionInternal) GetMaxValue() DivInt {
	return ^(^DivInt(0) << div.GetBitCount())
}

func (div *addressDivisionInternal) isMultiple() bool {
	vals := div.divisionValues
	if vals == nil {
		return false
	}
	return vals.getDivisionValue() != vals.getUpperDivisionValue()
}

func (div *addressDivisionInternal) getDivisionValue() DivInt {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.getDivisionValue()
}

func (div *addressDivisionInternal) getUpperDivisionValue() DivInt {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.getUpperDivisionValue()
}

type AddressDivision struct {
	addressDivisionInternal
}

// Note: many of the methods below are not public to addressDivisionInternal because segments have corresponding methods using segment values
func (div *AddressDivision) GetDivisionValue() DivInt {
	return div.getDivisionValue()
}

func (div *AddressDivision) GetUpperDivisionValue() DivInt {
	return div.getUpperDivisionValue()
}

func (div *AddressDivision) IsMultiple() bool {
	return div.isMultiple()
}

func (div *AddressDivision) GetMaxValue() DivInt {
	return ^(^DivInt(0) << div.GetBitCount())
}

/**
 * Returns whether this item matches the value of zero
 *
 * @return whether this item matches the value of zero
 */
func (div *AddressDivision) isZero() bool {
	return !div.IsMultiple() && div.IncludesZero()
}

/**
 * Returns whether this item includes the value of zero within its range
 *
 * @return whether this item includes the value of zero within its range
 */
func (div *AddressDivision) IncludesZero() bool {
	return div.getDivisionValue() == 0
}

/**
 * Returns whether this item matches the maximum possible value for the address type or version
 *
 * @return whether this item matches the maximum possible value
 */
func (div *AddressDivision) IsMax() bool {
	return !div.IsMultiple() && div.IncludesMax()
}

/**
 * Returns whether this item includes the maximum possible value for the address type or version within its range
 *
 * @return whether this item includes the maximum possible value within its range
 */
func (div *AddressDivision) IncludesMax() bool {
	return div.getUpperDivisionValue() == div.GetMaxValue()
}

/**
 * whether this address item represents all possible values attainable by an address item of this type
 *
 * @return whether this address item represents all possible values attainable by an address item of this type,
 * or in other words, both includesZero() and includesMax() return true
 */
func (div *AddressDivision) IsFullRange() bool {
	return div.IncludesZero() && div.IncludesMax()
}

func (div *AddressDivision) toPrefixedDivision(divPrefixLength PrefixLen) *AddressDivision {
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
			return div
		}
	} else {
		return div
	}
	lower := div.GetDivisionValue()
	upper := div.GetUpperDivisionValue()

	newVals := div.deriveNew(lower, upper, divPrefixLength)
	return createAddressDivision(newVals)

}

func (div *AddressDivision) toPrefixedNetworkDivision(divPrefixLength PrefixLen) *AddressDivision {
	return div.toNetworkDivision(divPrefixLength, true)
}

func (div *AddressDivision) toNetworkDivision(divPrefixLength PrefixLen, withPrefixLength bool) *AddressDivision {
	vals := div.divisionValues
	if vals == nil {
		return div
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
			return div
		}
	} else {
		withPrefixLength = false
		divPrefixLength = nil
		if div.getDivisionPrefixLength() == nil {
			return div
		}
	}
	newVals := div.deriveNew(newLower, newUpper, divPrefixLength)
	return createAddressDivision(newVals)
}

func (div *AddressDivision) ToAddressSegment() *AddressSegment {
	if div.GetBitCount() <= SegIntSize {
		return (*AddressSegment)(unsafe.Pointer(div))
	}
	return nil
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

func testRange(lowerValue, upperValue, finalUpperValue, networkMask, hostMask DivInt) bool {
	return lowerValue == (lowerValue&networkMask) && finalUpperValue == (upperValue|hostMask)
}

func divsSame(onePref, twoPref PrefixLen, oneVal, twoVal, oneUpperVal, twoUpperVal DivInt) bool {
	return PrefixEquals(onePref, twoPref) &&
		oneVal == twoVal && oneUpperVal == twoUpperVal
}
