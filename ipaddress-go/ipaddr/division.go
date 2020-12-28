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

	GetByteCount() int // TODO maybe drop this and instead derive from GetBitCount like GetMaxValue() and GetMaxSegmentValue()
}

// DivisionValues represents divisions with values that are 64 bits or less
type divisionValues interface {
	divisionValuesBase

	// getDivisionValue gets the lower value for the division
	getDivisionValue() DivInt

	// getUpperDivisionValue gets the upper value for the division
	getUpperDivisionValue() DivInt

	// getDivisionPrefixLength provides the prefix length
	// if is aligned is true and the prefix is non-nil, any divisions that follow in the same grouping have a zero-length prefix
	getDivisionPrefixLength() PrefixLen

	// getSegmentValue gets the lower value truncated to a SegInt
	getSegmentValue() SegInt

	// getUpperSegmentValue gets the upper value truncated to a SegInt
	getUpperSegmentValue() SegInt

	// deriveNew produces a new division with the same bit count as the old
	deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues

	// getCache returns a cache for this divisions which cache their values, or nil otherwise
	getCache() *divCache
}

type divCache struct {
	sync.RWMutex

	lowerBytes, upperBytes             []byte
	cachedString, cachedWildcardString string
	isSinglePrefixBlock                boolSetting

	// I decided it makes no sense to do this, so network will go away
	//network                            AddressNetwork // never nil // equivalent to overriding getNetwork(), ToIPvX(), IsIPvxConvertible(), etc, in Java, allows you to supply your own conversion
}

//TODO everything must become a Stringer, following the pattern of toString() in Java

type addressDivisionInternal struct {
	divisionValues
}

func (div *addressDivisionInternal) String() string {
	if div.isMultiple() {
		return fmt.Sprintf("%x-%x", div.getDivisionValue(), div.GetUpperDivisionValue())
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
	vals := div.divisionValues
	if vals == nil {
		return false
	}
	return div.getDivisionPrefixLength() != nil
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

type AddressDivision struct {
	addressDivisionInternal
}

// Note: many of the methods below are not public to addressDivisionInternal because segments have corresponding methods using segment values
//func (div *AddressDivision) getDivisionValue() DivInt {
//	vals := div.divisionValues
//	if vals == nil {
//		return 0
//	}
//	return vals.getDivisionValue()
//}
//
//func (div *AddressDivision) getUpperDivisionValue() DivInt {
//	vals := div.divisionValues
//	if vals == nil {
//		return 0
//	}
//	return vals.getUpperDivisionValue()
//}

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
	return &AddressDivision{addressDivisionInternal{divisionValues: newVals}}
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
		if PrefixEquals(divPrefixLength, div.getDivisionPrefixLength()) &&
			newLower == lower && newUpper == upper {
			return div
		}
	} else {
		withPrefixLength = false
		divPrefixLength = nil
		if div.getDivisionPrefixLength() == nil {
			return div
		}
	}
	newVals := div.deriveNew(DivInt(newLower), DivInt(newUpper), divPrefixLength)
	return &AddressDivision{addressDivisionInternal{divisionValues: newVals}}
}

func (div *AddressDivision) ToAddressSegment() *AddressSegment {
	//if _, ok := div.divisionValues.(segmentValues); ok {
	//	return (*AddressSegment)(unsafe.Pointer(div))
	//} else if div.GetBitCount() <= SegIntSize {
	//	return &AddressSegment{
	//		addressSegmentInternal{
	//			addressDivisionInternal{
	//				wrappedDivisionValues{div.divisionValues},
	//			},
	//		},
	//	}
	//}
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
