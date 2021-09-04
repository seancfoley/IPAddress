package ipaddr

import (
	"math/big"
	"math/bits"
	"strings"
	"sync/atomic"
	"unsafe"
)

// DivInt is an integer type for holding generic division values, which can be larger than segment values
type DivInt = uint64

const DivIntSize = 64

type divderiver interface {
	// deriveNew produces a new division with the same bit count as the old
	deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues
}

type segderiver interface {
	// deriveNew produces a new segment with the same bit count as the old
	deriveNewMultiSeg(val, upperVal SegInt, prefLen PrefixLen) divisionValues

	// deriveNew produces a new segment with the same bit count as the old
	deriveNewSeg(val SegInt, prefLen PrefixLen) divisionValues
}

type segmentValues interface {
	// getSegmentValue gets the lower value for a segment
	getSegmentValue() SegInt

	// getUpperSegmentValue gets the upper value for a segment
	getUpperSegmentValue() SegInt

	segderiver
}

// DivisionValues represents divisions with values that are 64 bits or less
type divisionValues interface {
	divisionValuesBase

	// getDivisionValue gets the lower value for a division
	getDivisionValue() DivInt

	// getUpperDivisionValue gets the upper value for a division
	getUpperDivisionValue() DivInt

	divderiver

	segmentValues
}

func newDivValues(value, upperValue DivInt, prefLen PrefixLen, bitCount BitCount, defaultRadix int) *divValues {
	return &divValues{
		value:        value,
		upperValue:   upperValue,
		prefLen:      prefLen,
		bitCount:     bitCount,
		defaultRadix: defaultRadix,
	}
}

type divValues struct {
	bitCount          BitCount
	value, upperValue DivInt
	prefLen           PrefixLen
	defaultRadix      int
	cache             divCache
}

func (div *divValues) getBitCount() BitCount {
	return div.bitCount
}

func (div *divValues) getByteCount() int {
	return (int(div.getBitCount()) + 7) >> 3
}

func (div *divValues) getDivisionPrefixLength() PrefixLen {
	return div.prefLen
}

func (div *divValues) getValue() *BigDivInt {
	return big.NewInt(int64(div.value))
}

func (div *divValues) getUpperValue() *BigDivInt {
	return big.NewInt(int64(div.upperValue))
}

func (div *divValues) includesZero() bool {
	return div.value == 0
}

func (div *divValues) includesMax() bool {
	allOnes := ^DivInt(0)
	return div.upperValue == allOnes & ^(allOnes<<uint(div.getBitCount()))
}

func (div *divValues) isMultiple() bool {
	return div.value != div.upperValue
}

func (div *divValues) getCount() *big.Int {
	res := new(big.Int)
	return res.SetUint64(uint64(div.upperValue-div.value)).Add(res, bigOneConst())
}

func (div *divValues) calcBytesInternal() (bytes, upperBytes []byte) {
	return calcBytesInternal(div.getByteCount(), div.getDivisionValue(), div.getUpperDivisionValue())
}

func calcBytesInternal(byteCount int, val, upperVal DivInt) (bytes, upperBytes []byte) {
	byteIndex := byteCount - 1
	isMultiple := val != upperVal //seg.isMultiple()
	bytes = make([]byte, byteCount)
	if isMultiple {
		upperBytes = make([]byte, byteCount)
	} else {
		upperBytes = bytes
	}
	for {
		bytes[byteIndex] |= byte(val)
		val >>= 8
		if isMultiple {
			upperBytes[byteIndex] |= byte(upperVal)
			upperVal >>= 8
		}
		if byteIndex == 0 {
			return bytes, upperBytes
		}
		byteIndex--
	}
}

func (div *divValues) getCache() *divCache {
	return &div.cache
}

func (div *divValues) getAddrType() addrType {
	return zeroType
}

func (div *divValues) getDivisionValue() DivInt {
	return div.value
}

func (div *divValues) getUpperDivisionValue() DivInt {
	return div.upperValue
}

func (div *divValues) deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues {
	return NewRangePrefixDivision(val, upperVal, prefLen, div.bitCount, div.defaultRadix)
}

func (div *divValues) getSegmentValue() SegInt {
	return SegInt(div.value)
}

func (div *divValues) getUpperSegmentValue() SegInt {
	return SegInt(div.upperValue)
}

func (div *divValues) deriveNewMultiSeg(val, upperVal SegInt, prefLen PrefixLen) divisionValues {
	return NewRangePrefixDivision(DivInt(val), DivInt(upperVal), prefLen, div.bitCount, div.defaultRadix)
}

func (div *divValues) deriveNewSeg(val SegInt, prefLen PrefixLen) divisionValues {
	return NewPrefixDivision(DivInt(val), prefLen, div.bitCount, div.defaultRadix)
}

var _ divisionValues = &divValues{}

func createAddressDivision(vals divisionValues) *AddressDivision {
	return &AddressDivision{
		addressDivisionInternal{
			addressDivisionBase: addressDivisionBase{vals},
		},
	}
}

type addressDivisionInternal struct {
	addressDivisionBase
}

var (
	// wildcards differ, here we use only range since div size not implicit
	octalParamsDiv   = new(IPStringOptionsBuilder).SetRadix(8).SetSegmentStrPrefix(OctalPrefix).SetWildcards(rangeWildcard).ToOptions()
	hexParamsDiv     = new(IPStringOptionsBuilder).SetRadix(16).SetSegmentStrPrefix(HexPrefix).SetWildcards(rangeWildcard).ToOptions()
	decimalParamsDiv = new(IPStringOptionsBuilder).SetRadix(10).SetWildcards(rangeWildcard).ToOptions()
)

func (div *addressDivisionInternal) String() string { // this can be moved to addressDivisionBase when we have ContainsPrefixBlock and similar methods implemented for big.Int in the base
	radix := div.getDefaultTextualRadix()
	var opts IPStringOptions
	switch radix {
	case 16:
		opts = hexParamsDiv
	case 10:
		opts = decimalParamsDiv
	case 8:
		opts = octalParamsDiv
	default:
		opts = new(IPStringOptionsBuilder).SetRadix(radix).SetWildcards(rangeWildcard).ToOptions()
	}
	return div.toString(opts)
}

func (div *addressDivisionInternal) toString(opts StringOptions) string {
	builder := strings.Builder{}
	params := toParams(opts)
	builder.Grow(params.getDivisionStringLength(div))
	params.appendDivision(&builder, div)
	return builder.String()
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
	if divisionPrefixLen <= 0 {
		return divisionValue == 0 && upperValue == div.getMaxValue()
	}
	bitCount := div.GetBitCount()
	if divisionPrefixLen >= bitCount {
		return true
	}
	var ones = ^DivInt(0)
	var divisionBitMask DivInt = ^(ones << uint(bitCount))
	var divisionPrefixMask DivInt = ones << uint(bitCount-divisionPrefixLen)
	var divisionNonPrefixMask = ^divisionPrefixMask
	return testRange(divisionValue,
		upperValue,
		upperValue,
		divisionPrefixMask&divisionBitMask,
		divisionNonPrefixMask)
}

// Returns whether the given range of segmentValue to upperValue is equivalent to the range of segmentValue with the prefix of divisionPrefixLen
func (div *addressDivisionInternal) isSinglePrefix(divisionValue, upperValue DivInt, divisionPrefixLen BitCount) bool {
	bitCount := div.GetBitCount()
	shift := uint(bitCount - divisionPrefixLen)
	return (divisionValue >> shift) == (upperValue >> shift)
}

// Returns whether the given range of segmentValue to upperValue is equivalent to the range of segmentValue with the prefix of divisionPrefixLen
func (div *addressDivisionInternal) isSinglePrefixBlock(divisionValue, upperValue DivInt, divisionPrefixLen BitCount) bool {
	if divisionPrefixLen == 0 {
		return divisionValue == 0 && upperValue == div.getMaxValue()
	}
	bitCount := div.GetBitCount()
	ones := ^DivInt(0)
	divisionBitMask := ^(ones << uint(bitCount))
	divisionPrefixMask := ones << uint(bitCount-divisionPrefixLen)
	divisionHostMask := ^divisionPrefixMask
	return testRange(divisionValue,
		divisionValue,
		upperValue,
		divisionPrefixMask&divisionBitMask,
		divisionHostMask)
}

func (div *addressDivisionInternal) ContainsPrefixBlock(prefixLen BitCount) bool {
	prefixLen = checkDiv(div, prefixLen)
	return div.isPrefixBlockVals(div.getDivisionValue(), div.getUpperDivisionValue(), prefixLen)
}

func (div *addressDivisionInternal) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	prefixLen = checkDiv(div, prefixLen)
	return div.isSinglePrefixBlock(div.getDivisionValue(), div.getUpperDivisionValue(), prefixLen)
}

func (div *addressDivisionInternal) GetMinPrefixLenForBlock() BitCount {
	cache := div.getCache()
	if cache == nil {
		return GetMinPrefixLenForBlock(div.getDivisionValue(), div.getUpperDivisionValue(), div.GetBitCount())
	}
	res := cache.minPrefLenForBlock
	if res == nil {
		res = cacheBitCount(GetMinPrefixLenForBlock(div.getDivisionValue(), div.getUpperDivisionValue(), div.GetBitCount()))
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.minPrefLenForBlock))
		atomic.StorePointer(dataLoc, unsafe.Pointer(res))
	}
	return *res
}

func (div *addressDivisionInternal) GetPrefixLenForSingleBlock() PrefixLen {
	return GetPrefixLenForSingleBlock(div.getDivisionValue(), div.getUpperDivisionValue(), div.GetBitCount())
}

// return whether the division range includes the block of values for the division prefix length,
// or false if the division has no prefix length
func (div *addressDivisionInternal) isPrefixBlock() bool {
	prefLen := div.getDivisionPrefixLength()
	return prefLen != nil && div.containsPrefixBlock(*prefLen)
}

func (div *addressDivisionInternal) getMaxValue() DivInt {
	return ^(^DivInt(0) << uint(div.GetBitCount()))
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

func (div *addressDivisionInternal) matches(value DivInt) bool {
	return !div.IsMultiple() && value == div.getDivisionValue()
}

func (div *addressDivisionInternal) matchesWithMask(value, mask DivInt) bool {
	if div.IsMultiple() {
		//we want to ensure that any of the bits that can change from value to upperValue is masked out (zeroed) by the mask.
		//In other words, when masked we need all values represented by this segment to become just a single value
		diffBits := div.getDivisionValue() ^ div.getUpperDivisionValue()
		leadingZeros := bits.LeadingZeros64(diffBits)
		//the bits that can change are all bits following the first leadingZero bits
		//all the bits that follow must be zeroed out by the mask
		fullMask := ^DivInt(0) >> uint(leadingZeros)
		if (fullMask & mask) != 0 {
			return false
		} //else we know that the mask zeros out all the bits that can change from value to upperValue, so now we just compare with either one
	}
	return value == (div.getDivisionValue() & mask)
}

// matchesWithMask returns whether masking with the given mask results in a valid contiguous range for this segment,
// and if it does, if it matches the range obtained when masking the given values with the same mask.
func (div *addressDivisionInternal) matchesValsWithMask(lowerValue, upperValue, mask DivInt) bool {
	if lowerValue == upperValue {
		return div.matchesWithMask(lowerValue, mask)
	}
	if !div.IsMultiple() {
		// lowerValue and upperValue are not the same, so impossible to match those two values with a single value
		return false
	}
	thisValue := div.getDivisionValue()
	thisUpperValue := div.getUpperDivisionValue()
	masker := maskRange(thisValue, thisUpperValue, mask, div.getMaxValue())
	if !masker.IsSequential() {
		return false
	}
	return lowerValue == masker.GetMaskedLower(thisValue, mask) && upperValue == masker.GetMaskedUpper(thisUpperValue, mask)
}

func (div *addressDivisionInternal) toPrefixedNetworkDivision(divPrefixLength PrefixLen) *AddressDivision {
	return div.toNetworkDivision(divPrefixLength, true)
}

func (div *addressDivisionInternal) toNetworkDivision(divPrefixLength PrefixLen, withPrefixLength bool) *AddressDivision {
	vals := div.divisionValues
	if vals == nil {
		return div.toAddressDivision()
	}
	lower := div.getDivisionValue()
	upper := div.getUpperDivisionValue()
	var newLower, newUpper DivInt
	hasPrefLen := divPrefixLength != nil
	if hasPrefLen {
		prefBits := *divPrefixLength
		bitCount := div.GetBitCount()
		prefBits = checkBitCount(prefBits, bitCount)
		mask := ^DivInt(0) << uint(bitCount-prefBits)
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

func (div *addressDivisionInternal) toPrefixedHostDivision(divPrefixLength PrefixLen) *AddressDivision {
	return div.toHostDivision(divPrefixLength, true)
}

func (div *addressDivisionInternal) toHostDivision(divPrefixLength PrefixLen, withPrefixLength bool) *AddressDivision {
	vals := div.divisionValues
	if vals == nil {
		return div.toAddressDivision()
	}
	lower := div.getDivisionValue()
	upper := div.getUpperDivisionValue()
	//var newLower, newUpper DivInt
	hasPrefLen := divPrefixLength != nil
	var mask SegInt
	if hasPrefLen {
		prefBits := *divPrefixLength
		bitCount := div.GetBitCount()
		prefBits = checkBitCount(prefBits, bitCount)
		mask = ^(^SegInt(0) << uint(bitCount-prefBits))
	}
	divMask := uint64(mask)
	maxVal := uint64(^SegInt(0))
	masker := maskRange(lower, upper, divMask, maxVal)
	newLower, newUpper := masker.GetMaskedLower(lower, divMask), masker.GetMaskedUpper(upper, divMask)
	if !withPrefixLength {
		divPrefixLength = nil
	}
	if divsSame(divPrefixLength, div.getDivisionPrefixLength(), newLower, lower, newUpper, upper) {
		return div.toAddressDivision()
	}
	newVals := div.deriveNew(newLower, newUpper, divPrefixLength)
	return createAddressDivision(newVals)
}

func (div *addressDivisionInternal) toPrefixedDivision(divPrefixLength PrefixLen) *AddressDivision {
	hasPrefLen := divPrefixLength != nil
	bitCount := div.GetBitCount()
	if hasPrefLen {
		prefBits := *divPrefixLength
		prefBits = checkBitCount(prefBits, bitCount)
		if div.isPrefixed() && prefBits == *div.getDivisionPrefixLength() {
			return div.toAddressDivision()
		}
	} else {
		return div.toAddressDivision()
	}
	lower := div.getDivisionValue()
	upper := div.getUpperDivisionValue()
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

func (div *addressDivisionInternal) IsSinglePrefix(divisionPrefixLength BitCount) bool {
	bitCount := div.GetBitCount()
	divisionPrefixLength = checkBitCount(divisionPrefixLength, bitCount)
	return div.isSinglePrefix(div.getDivisionValue(), div.getUpperDivisionValue(), divisionPrefixLength)
}

func (div *addressDivisionInternal) GetPrefixCountLen(divisionPrefixLength BitCount) *big.Int {
	if div.IsFullRange() {
		return bigZero().Add(bigOneConst(), bigZero().SetUint64(div.getMaxValue()))
	}
	bitCount := div.GetBitCount()
	divisionPrefixLength = checkBitCount(divisionPrefixLength, bitCount)
	shiftAdjustment := bitCount - divisionPrefixLength
	count := ((div.getUpperDivisionValue() >> uint(shiftAdjustment)) - (div.getDivisionValue() >> uint(shiftAdjustment))) + 1
	return bigZero().SetUint64(count)
}

func (div *addressDivisionInternal) Equals(other DivisionType) bool {
	if otherDiv, ok := other.(StandardDivisionType); ok {
		if div.IsMultiple() {
			if other.IsMultiple() {
				matches, _ := div.matchesStructure(other)
				if !matches {
					return false
				}
				otherDivision := otherDiv.ToAddressDivision()
				return divValsSame(div.getDivisionValue(), otherDivision.GetDivisionValue(),
					div.getUpperDivisionValue(), otherDivision.GetUpperDivisionValue())
			} else {
				return false
			}
		} else if other.IsMultiple() {
			return false
		} else {
			matches, _ := div.matchesStructure(other)
			otherDivision := otherDiv.ToAddressDivision()
			return matches && divValSame(div.getDivisionValue(), otherDivision.GetDivisionValue())
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

func (div *addressDivisionInternal) CompareTo(item AddressItem) int {
	return CountComparator.Compare(div.toAddressDivision(), item)
}

func (div *addressDivisionInternal) getStringAsLower() string {
	if seg := div.toAddressDivision().ToIPAddressSegment(); seg != nil {
		return seg.getStringAsLower()
	}
	return div.getStringFromStringer(div.getDefaultLowerString)
}

func (div *addressDivisionInternal) getString() string {
	if !div.IsMultiple() {
		return div.getStringFromStringer(div.getDefaultLowerString)
	} else {
		return div.getStringFromStringer(div.getDefaultRangeString)
	}
	//return div.getStringFromStringer(func() string {
	//	if !div.IsMultiple() {
	//		return div.getDefaultLowerString()
	//	} else {
	//		return div.getDefaultRangeString()
	//	}
	//})
}

func (div *addressDivisionInternal) getStringFromStringer(stringer func() string) string {
	if div.divisionValues != nil {
		if cache := div.getCache(); cache != nil {
			return cacheStr(&cache.cachedString, stringer)
		}
	}
	return stringer()
}

func (div *addressDivisionInternal) GetString() string {
	if seg := div.toAddressDivision().ToIPAddressSegment(); seg != nil {
		return seg.GetString()
	}
	return div.getString()
}

func (div *addressDivisionInternal) GetWildcardString() string {
	if seg := div.toAddressDivision().ToIPAddressSegment(); seg != nil {
		return seg.GetWildcardString()
	}
	return div.getString() // same string as GetString() when not an IP segment
}

func (div *addressDivisionInternal) getDefaultRangeStringVals(val1, val2 uint64, radix int) string {
	return getDefaultRangeStringVals(div, val1, val2, radix)
}

func (div *addressDivisionInternal) buildDefaultRangeString(radix int) string {
	return buildDefaultRangeString(div, radix)
}

func (div *addressDivisionInternal) getLowerStringLength(radix int) int {
	return toUnsignedStringLength(div.getDivisionValue(), radix)
}

func (div *addressDivisionInternal) getUpperStringLength(radix int) int {
	return toUnsignedStringLength(div.getUpperDivisionValue(), radix)
}

func (div *addressDivisionInternal) getLowerString(radix int, uppercase bool, appendable *strings.Builder) {
	toUnsignedStringCased(div.getDivisionValue(), radix, 0, uppercase, appendable)
}

func (div *addressDivisionInternal) getLowerStringChopped(radix int, choppedDigits int, uppercase bool, appendable *strings.Builder) {
	toUnsignedStringCased(div.getDivisionValue(), radix, choppedDigits, uppercase, appendable)
}

func (div *addressDivisionInternal) getUpperString(radix int, uppercase bool, appendable *strings.Builder) {
	toUnsignedStringCased(div.getUpperDivisionValue(), radix, 0, uppercase, appendable)
}

func (div *addressDivisionInternal) getUpperStringMasked(radix int, uppercase bool, appendable *strings.Builder) {
	if seg := div.toAddressDivision().ToIPAddressSegment(); seg != nil {
		seg.getUpperStringMasked(radix, uppercase, appendable)
	} else if div.isPrefixed() {
		upperValue := div.getUpperDivisionValue()
		mask := ^DivInt(0) << uint(div.GetBitCount()-*div.getDivisionPrefixLength())
		//mask := ^(^DivInt(0) >> *seg.GetSegmentPrefixLen())
		//mask := seg.GetSegmentNetworkMask(*seg.GetSegmentPrefixLen())
		//return seg.GetMaxValue() & (^SegInt(0) << (bc - bits))
		upperValue &= mask
		toUnsignedStringCased(upperValue, radix, 0, uppercase, appendable)
	} else {
		div.getUpperString(radix, uppercase, appendable)
	}
}

func (div *addressDivisionInternal) getSplitLowerString(radix int, choppedDigits int, uppercase bool,
	splitDigitSeparator byte, reverseSplitDigits bool, stringPrefix string, appendable *strings.Builder) {
	toSplitUnsignedString(div.getDivisionValue(), radix, choppedDigits, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable)
}

func (div *addressDivisionInternal) getSplitRangeString(rangeSeparator string, wildcard string, radix int, uppercase bool,
	splitDigitSeparator byte, reverseSplitDigits bool, stringPrefix string, appendable *strings.Builder) IncompatibleAddressError {
	return toUnsignedSplitRangeString(
		div.getDivisionValue(),
		div.getUpperDivisionValue(),
		rangeSeparator,
		wildcard,
		radix,
		uppercase,
		splitDigitSeparator,
		reverseSplitDigits,
		stringPrefix,
		appendable)
}

func (div *addressDivisionInternal) getSplitRangeStringLength(rangeSeparator string, wildcard string, leadingZeroCount int, radix int, uppercase bool,
	splitDigitSeparator byte, reverseSplitDigits bool, stringPrefix string) int {
	return toUnsignedSplitRangeStringLength(
		div.getDivisionValue(),
		div.getUpperDivisionValue(),
		rangeSeparator,
		wildcard,
		leadingZeroCount,
		radix,
		uppercase,
		splitDigitSeparator,
		reverseSplitDigits,
		stringPrefix)
}

func (div *addressDivisionInternal) getRangeDigitCount(radix int) int {
	if !div.IsMultiple() {
		return 0
	}
	if radix == 16 {
		prefix := div.GetMinPrefixLenForBlock()
		bitCount := div.GetBitCount()
		if prefix < bitCount && div.ContainsSinglePrefixBlock(prefix) {
			bitsPerCharacter := BitCount(4)
			if prefix%bitsPerCharacter == 0 {
				return int((bitCount - prefix) / bitsPerCharacter)
			}
		}
		return 0
	}
	value := div.getDivisionValue()
	upperValue := div.getUpperDivisionValue()
	maxValue := div.getMaxValue()
	factorRadix := DivInt(radix)
	factor := factorRadix
	numDigits := 1
	for {
		lowerRemainder := value % factor
		if lowerRemainder == 0 {
			//Consider in ipv4 the segment 24_
			//what does this mean?  It means 240 to 249 (not 240 to 245)
			//Consider 25_.  It means 250-255.
			//so the last digit ranges between 0-5 or 0-9 depending on whether the front matches the max possible front of 25.
			//If the front matches, the back ranges from 0 to the highest value of 255.
			//if the front does not match, the back must range across all values for the radix (0-9)
			var max DivInt
			if maxValue/factor == upperValue/factor {
				max = maxValue % factor
			} else {
				max = factor - 1
			}
			upperRemainder := upperValue % factor
			if upperRemainder == max {
				//whatever range there is must be accounted entirely by range digits, otherwise the range digits is 0
				//so here we check if that is the case
				if upperValue-upperRemainder == value {
					return numDigits
				} else {
					numDigits++
					factor *= factorRadix
					continue
				}
			}
		}
		return 0
	}
}

// if leadingZeroCount is -1, returns the number of leading zeros for maximum width, based on the width of the value
func (div *addressDivisionInternal) adjustLowerLeadingZeroCount(leadingZeroCount int, radix int) int {
	return div.adjustLeadingZeroCount(leadingZeroCount, div.getDivisionValue(), radix)
}

// if leadingZeroCount is -1, returns the number of leading zeros for maximum width, based on the width of the value
func (div *addressDivisionInternal) adjustUpperLeadingZeroCount(leadingZeroCount int, radix int) int {
	return div.adjustLeadingZeroCount(leadingZeroCount, div.getUpperDivisionValue(), radix)
}

func (div *addressDivisionInternal) adjustLeadingZeroCount(leadingZeroCount int, value DivInt, radix int) int {
	if leadingZeroCount < 0 {
		width := getDigitCount(value, div.GetBitCount(), radix) //static
		num := div.getMaxDigitCountRadix(radix) - width
		if num < 0 {
			return 0
		}
		return num
	}
	return leadingZeroCount
}

func (div *addressDivisionInternal) getDigitCount(radix int) int {
	if !div.IsMultiple() && radix == div.getDefaultTextualRadix() { //optimization - just get the string, which is cached, which speeds up further calls to this or getString()
		return len(div.GetWildcardString())
	}
	return getDigitCount(div.getUpperDivisionValue(), div.GetBitCount(), radix) //static
}

func (div *addressDivisionInternal) getMaxDigitCountRadix(radix int) int {
	//if radix == 10 || radix == 16 {
	//	return div.getMaxDigitCount()
	//}
	return getMaxDigitCount(radix, div.GetBitCount(), div.getMaxValue()) //static
}

// returns the number of digits for the maximum possible value of the division when using the default radix
func (div *addressDivisionInternal) getMaxDigitCount() int {
	return div.getMaxDigitCountRadix(div.getDefaultTextualRadix())
	//xxx
	//return int((div.GetBitCount() + 7) >> 2) // works for hex chars, the default, but also IPv4 where bitcount of 8 results in result of 3
}

// A simple string using just the lower value and the default radix.
func (div *addressDivisionInternal) getDefaultLowerString() string {
	return toDefaultString(div.getDivisionValue(), div.getDefaultTextualRadix())
}

// A simple string using just the lower and upper values and the default radix, separated by the default range character.
func (div *addressDivisionInternal) getDefaultRangeString() string {
	return div.getDefaultRangeStringVals(div.getDivisionValue(), div.getUpperDivisionValue(), div.getDefaultTextualRadix())
}

// getDefaultSegmentWildcardString() is the wildcard string to be used when producing the default strings with getString() or getWildcardString()
//
// Since no parameters for the string are provided, default settings are used, but they must be consistent with the address.
//
// For instance, generally the '*' is used as a wildcard to denote all possible values for a given segment,
// but in some cases that character is used for a segment separator.
//
// Note that this only applies to "default" settings, there are additional string methods that allow you to specify these separator characters.
// Those methods must be aware of the defaults as well, to know when they can defer to the defaults and when they cannot.
func (div *addressDivisionInternal) getDefaultSegmentWildcardString() string {
	if seg := div.toAddressDivision().ToAddressSegment(); seg != nil {
		return seg.getDefaultSegmentWildcardString()
	}
	return "" // for divisions, the width is variable and max values can change, so using wildcards make no sense
}

// getDefaultRangeSeparatorString() is the wildcard string to be used when producing the default strings with getString() or getWildcardString()
//
// Since no parameters for the string are provided, default settings are used, but they must be consistent with the address.
//
//For instance, generally the '-' is used as a range separator, but in some cases that character is used for a segment separator.
//
// Note that this only applies to "default" settings, there are additional string methods that allow you to specify these separator characters.
// Those methods must be aware of the defaults as well, to know when they can defer to the defaults and when they cannot.
func (div *addressDivisionInternal) getDefaultRangeSeparatorString() string {
	return "-"
}

func NewDivision(val DivInt, bitCount BitCount, defaultRadix int) *AddressDivision {
	return NewRangePrefixDivision(val, val, nil, bitCount, defaultRadix)
}

func NewRangeDivision(val, upperVal DivInt, bitCount BitCount, defaultRadix int) *AddressDivision {
	return NewRangePrefixDivision(val, upperVal, nil, bitCount, defaultRadix)
}

func NewPrefixDivision(val DivInt, prefixLen PrefixLen, bitCount BitCount, defaultRadix int) *AddressDivision {
	return NewRangePrefixDivision(val, val, prefixLen, bitCount, defaultRadix)
}

func NewRangePrefixDivision(val, upperVal DivInt, prefixLen PrefixLen, bitCount BitCount, defaultRadix int) *AddressDivision {
	return &AddressDivision{
		addressDivisionInternal{
			addressDivisionBase{newDivValues(val, upperVal, prefixLen, bitCount, defaultRadix)},
		},
	}
}

// AddressDivision represents an arbitrary division in an address or address division grouping.
// Divisions that were converted from IPv4, IPv6 or MAC segments can be converted back to the same segment type and version.
// Divisions that were not converted from IPv4, IPv6 or MAC cannot be converted to segments.
type AddressDivision struct {
	addressDivisionInternal
}

//Note: many of the methods below are not public to addressDivisionInternal because segments have corresponding methods using segment values

// GetDivisionValue returns the lower division value
func (div *AddressDivision) GetDivisionValue() DivInt {
	return div.getDivisionValue()
}

// GetUpperDivisionValue returns the upper division value
func (div *AddressDivision) GetUpperDivisionValue() DivInt {
	return div.getUpperDivisionValue()
}

func (div *AddressDivision) Matches(value DivInt) bool {
	return div.matches(value)
}

func (div *AddressDivision) MatchesWithMask(value, mask DivInt) bool {
	return div.matchesWithMask(value, mask)
}

func (div *AddressDivision) MatchesValsWithMask(lowerValue, upperValue, mask DivInt) bool {
	return div.matchesValsWithMask(lowerValue, upperValue, mask)
}

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

func cacheStrPtr(cachedString **string, str *string) {
	cachedVal := *cachedString
	if cachedVal == nil {
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(cachedString))
		atomic.StorePointer(dataLoc, unsafe.Pointer(str))
	}
	return
}

func cacheStr(cachedString **string, stringer func() string) (str string) {
	cachedVal := *cachedString
	if cachedVal == nil {
		str = stringer()
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(cachedString))
		atomic.StorePointer(dataLoc, unsafe.Pointer(&str))
	} else {
		str = *cachedVal
	}
	return
}

func cacheStrErr(cachedString **string, stringer func() (string, IncompatibleAddressError)) (str string, err IncompatibleAddressError) {
	cachedVal := *cachedString
	if cachedVal == nil {
		str, err = stringer()
		if err == nil {
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(cachedString))
			atomic.StorePointer(dataLoc, unsafe.Pointer(&str))
		}
	} else {
		str = *cachedVal
	}
	return
}
