package ipaddr

import (
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

	// getDivisionValue gets the lower value for the division
	getDivisionValue() DivInt

	// getUpperDivisionValue gets the upper value for the division
	getUpperDivisionValue() DivInt

	// getDivisionPrefixLength provides the prefix length
	// if is aligned is true and the prefix is non-nil, any divisions that follow in the same grouping have a zero-length prefix
	getDivisionPrefixLength() PrefixLen

	getLower() (divisionValues, *divCache)

	getUpper() (divisionValues, *divCache)
}

type divCache struct {
	sync.RWMutex

	lowerBytes, upperBytes             []byte
	cachedString, cachedWildcardString string
	isSinglePrefixBlock                boolSetting

	// I decided it makes no sense to do this, so network will go
	//network                            AddressNetwork // never nil // equivalent to overriding getNetwork(), ToIPvX(), IsIPvxConvertible(), etc, in Java, allows you to supply your own conversion
}

type addressDivisionInternal struct {
	divisionValues

	cache *divCache
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
func (div *AddressDivision) isFullRange() bool {
	return div.IncludesZero() && div.IncludesMax()
}

func (div *AddressDivision) ToAddressSegment() *AddressSegment {
	if _, ok := div.divisionValues.(segmentValues); ok {
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
