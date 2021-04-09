package ipaddr

import (
	"math/big"
	"sync/atomic"
	"unsafe"
)

// TODO we must be careful that any methods we grab from Java addressDivisionBase are put in the right place and done the right way.
// Most are string-related and byte-related.
// addressDivisionBase is a base for both standard and large divisions.
// Standard divisions are divisions up to 64 bits of length, large are divisions of any length.
// With standard divisions, you can use GetValue/GetUpperValue and use DivInt integers for the values.
// For large divisions, you must use big.Int instances.

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

type addressDivisionBase struct {
	divisionValues //TODO this is not quite right.  Should be divisionValuesBase.  Not sure the best route here.  Seems either type assertions or double field.  Or leave as is and do type assertions in large divs only.
}

func (div *addressDivisionBase) getDivisionPrefixLength() PrefixLen {
	vals := div.divisionValues
	if vals == nil {
		return nil
	}
	return vals.getDivisionPrefixLength()
}

func (div *addressDivisionBase) GetBitCount() BitCount {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.getBitCount()
}

func (div *addressDivisionBase) GetByteCount() int {
	vals := div.divisionValues
	if vals == nil {
		return 0
	}
	return vals.getByteCount()
}

func (div *addressDivisionBase) GetValue() *big.Int {
	vals := div.divisionValues
	if vals == nil {
		return bigZero()
	}
	return vals.getValue()
}

func (div *addressDivisionBase) GetUpperValue() *big.Int {
	vals := div.divisionValues
	if vals == nil {
		return bigZero()
	}
	return vals.getUpperValue()
}

func (div *addressDivisionBase) GetBytes() []byte {
	if div.divisionValues == nil {
		return emptyBytes
	}
	cached := div.getBytes()
	return cloneBytes(cached)
}

func (div *addressDivisionBase) GetUpperBytes() []byte {
	if div.divisionValues == nil {
		return emptyBytes
	}
	cached := div.getUpperBytes()
	return cloneBytes(cached)
}

func (div *addressDivisionBase) CopyBytes(bytes []byte) []byte {
	if div.divisionValues == nil {
		if bytes != nil {
			return bytes
		}
		return emptyBytes
	}
	cached := div.getBytes()
	return getBytesCopy(bytes, cached)
}

func (div *addressDivisionBase) CopyUpperBytes(bytes []byte) []byte {
	if div.divisionValues == nil {
		if bytes != nil {
			return bytes
		}
		return emptyBytes
	}
	cached := div.getUpperBytes()
	return getBytesCopy(bytes, cached)
}

func (div *addressDivisionBase) getBytes() (bytes []byte) {
	bytes, _ = div.getBytesInternal()
	return
}

func (div *addressDivisionBase) getUpperBytes() (bytes []byte) {
	_, bytes = div.getBytesInternal()
	return
}

func (div *addressDivisionBase) getBytesInternal() (bytes, upperBytes []byte) {
	cache := div.getCache()
	if cache == nil {
		return div.calcBytesInternal()
	}
	cached := cache.cachedBytes
	if cached == nil {
		bytes, upperBytes = div.calcBytesInternal()
		cached = &bytesCache{
			lowerBytes: bytes,
			upperBytes: upperBytes,
		}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedBytes))
		atomic.StorePointer(dataLoc, unsafe.Pointer(cached))
	}
	return cached.lowerBytes, cached.upperBytes
}

func (div *addressDivisionBase) GetCount() *big.Int {
	if !div.IsMultiple() {
		return bigOne()
	}
	return div.getCount()
}

// The count of the number of distinct values within the prefix part of the address item, the bits that appear within the prefix length.
func (div *addressDivisionBase) GetPrefixCount(prefixLength BitCount) *big.Int {
	if prefixLength < 0 {
		return bigOne()
	}
	bitCount := div.GetBitCount()
	if prefixLength >= bitCount {
		return div.GetCount()
	}
	ushiftAdjustment := uint(bitCount - prefixLength)
	lower := div.GetValue()
	upper := div.GetUpperValue()
	upper.Rsh(upper, ushiftAdjustment)
	lower.Rsh(lower, ushiftAdjustment)
	upper.Sub(upper, lower).Add(upper, bigOneConst())
	return upper
}

func (div *addressDivisionBase) IsZero() bool {
	return !div.IsMultiple() && div.includesZero()
}

// Returns whether this item includes the value of zero within its range
func (div *addressDivisionBase) IncludesZero() bool {
	vals := div.divisionValues
	if vals == nil {
		return true
	}
	return vals.includesZero()
}

// Returns whether this item matches the maximum possible value for the address type or version
func (div *addressDivisionBase) IsMax() bool {
	return !div.IsMultiple() && div.includesMax()
}

// Returns whether this item includes the maximum possible value for the address type or version within its range
func (div *addressDivisionBase) IncludesMax() bool {
	vals := div.divisionValues
	if vals == nil {
		return false
	}
	return vals.includesMax()
}

// whether this address item represents all possible values attainable by an address item of this type
func (div *addressDivisionBase) IsFullRange() bool {
	return div.includesZero() && div.includesMax()
}

func (div *addressDivisionBase) IsMultiple() bool {
	vals := div.divisionValues
	if vals == nil {
		return false
	}
	return vals.isMultiple()
}

func (div *addressDivisionBase) getAddrType() addrType {
	vals := div.divisionValues
	if vals == nil {
		return zeroType
	}
	return vals.getAddrType()
}

func (div *addressDivisionBase) matchesStructure(other AddressGenericDivision) (res bool, addrType addrType) {
	addrType = div.getAddrType()
	if addrType != other.getAddrType() || (addrType.isNil() && (div.GetBitCount() != other.GetBitCount())) {
		return
	}
	res = true
	return
}

func (div *addressDivisionBase) Equals(other AddressGenericDivision) (res bool) {
	// TODO an identity/pointer comparison which requires we grab the *addressDivisionBase from AddressGenericDivision
	matches, _ := div.matchesStructure(other)
	if div.isMultiple() {
		return matches && bigDivValsSame(div.GetValue(), other.GetValue(),
			div.GetUpperValue(), other.GetUpperValue())
	} else if other.IsMultiple() {
		return false
	}
	return bigDivValSame(div.GetValue(), other.GetValue())
}

// returns the default radix for textual representations of addresses (10 for IPv4, 16 for IPv6)
func (div *addressDivisionBase) getDefaultTextualRadix() int {
	// when we support other division types, there may be more possibilities here
	addrType := div.getAddrType()
	if addrType.isIPv4() {
		return IPv4DefaultTextualRadix
	}
	return 16
}

func bigDivsSame(onePref, twoPref PrefixLen, oneVal, twoVal, oneUpperVal, twoUpperVal *big.Int) bool {
	return PrefixEquals(onePref, twoPref) &&
		oneVal.CmpAbs(twoVal) == 0 && oneUpperVal.CmpAbs(twoUpperVal) == 0
}

func bigDivValsSame(oneVal, twoVal, oneUpperVal, twoUpperVal *big.Int) bool {
	return oneVal.CmpAbs(twoVal) == 0 && oneUpperVal.CmpAbs(twoUpperVal) == 0
}

func bigDivValSame(oneVal, twoVal *big.Int) bool {
	return oneVal.CmpAbs(twoVal) == 0
}
