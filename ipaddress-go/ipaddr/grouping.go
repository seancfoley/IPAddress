package ipaddr

import (
	"fmt"
	"math/big"
	"sync/atomic"
	"unsafe"
)

func createGrouping(divs []*AddressDivision, prefixLength PrefixLen, addrType addrType) *AddressDivisionGrouping {
	grouping := &AddressDivisionGrouping{
		addressDivisionGroupingInternal{
			addressDivisionGroupingBase: addressDivisionGroupingBase{
				divisions:    standardDivArray{divs},
				prefixLength: prefixLength,
				addrType:     addrType,
				cache:        &valueCache{},
			},
		},
	}
	assignStringCache(&grouping.addressDivisionGroupingBase, addrType)
	return grouping
}

func createGroupingMultiple(divs []*AddressDivision, prefixLength PrefixLen, isMultiple bool) *AddressDivisionGrouping {
	result := createGrouping(divs, prefixLength, zeroType)
	result.isMultiple = isMultiple
	return result
}

func createInitializedGrouping(divs []*AddressDivision, prefixLength PrefixLen) *AddressDivisionGrouping {
	result := createGrouping(divs, prefixLength, zeroType)
	result.initMultiple() // assigns isMultiple
	return result
}

// Creates an arbitrary grouping of divisions.
// To create address sections or addresses, use the constructors that are specific to the address version or type.
// The AddressDivision instances can be created with the NewDivision, NewRangeDivision, NewPrefixDivision or NewRangePrefixDivision functions.
func NewDivisionGrouping(divs []*AddressDivision, prefixLength PrefixLen) *AddressDivisionGrouping {
	return createInitializedGrouping(divs, prefixLength)
}

var (
	emptyBytes = []byte{}
)

type addressDivisionGroupingInternal struct {
	addressDivisionGroupingBase

	// get rid of addressSegmentIndex and isExtended
	// You just don't need positionality from sections.
	// Being mixed or converting to IPv6 from MACSize are properties of the address.
	// isExtended really only used for IPv6/MACSize conversion.
	// addressSegmentindex really only used for mixed
	// Both of those are really "address-level" concepts.
	//
	// TODO LATER refactor to support infiniband, which will involve multiple types.
	// But that will be a joint effort with Java and will wait to later.

	// The index of the containing address where this section starts, only used by IPv6 where we trach the "IPv4-embedded" part of an address section
	//addressSegmentIndex int8

	//isExtended bool
}

func createSegmentArray(length int) []*AddressDivision {
	return make([]*AddressDivision, length)
}

func (grouping *addressDivisionGroupingInternal) initMultiple() {
	divCount := grouping.getDivisionCount()
	for i := divCount - 1; i >= 0; i-- {
		div := grouping.getDivision(i)
		if div.IsMultiple() {
			grouping.isMultiple = true
			return
		}
	}
	return
}

// getDivision returns the division or panics if the index is negative or too large
func (grouping *addressDivisionGroupingInternal) getDivision(index int) *AddressDivision {
	divsArray := grouping.divisions
	if divsArray != nil {
		return divsArray.(standardDivArray).divisions[index]
	}
	panic("invalid index") // must be consistent with above code which panics with invalid index
}

// getDivisionsInternal returns the divisions slice, only to be used internally
func (grouping *addressDivisionGroupingInternal) getDivisionsInternal() []*AddressDivision {
	divsArray := grouping.divisions
	if divsArray != nil {
		return divsArray.(standardDivArray).getDivisions()
	}
	return nil
}

func (grouping *addressDivisionGroupingInternal) getDivisionCount() int {
	divsArray := grouping.divisions
	if divsArray != nil {
		return divsArray.(standardDivArray).getDivisionCount()
	}
	return 0
}

func adjust1To1Indices(sourceStart, sourceEnd, sourceCount, targetStart, targetCount int) (newSourceStart, newSourceEnd, newTargetStart int) {
	//targetIndex := 0
	if sourceStart < 0 {
		targetStart -= sourceStart
		sourceStart = 0
	}
	// how many to copy?
	if sourceEnd > sourceCount { // end index exceeds available
		sourceEnd = sourceCount
	}
	calcCount := sourceEnd - sourceStart
	if calcCount <= 0 { // end index below start index
		return sourceStart, sourceStart, targetStart
	}
	// if not enough space in target, adjust count and end
	if space := targetCount - targetStart; calcCount > space {
		if space <= 0 {
			return sourceStart, sourceStart, targetStart
		}
		sourceEnd = sourceStart + space
	}
	return sourceStart, sourceEnd, targetStart
}

func adjustIndices(
	startIndex, endIndex, sourceCount,
	replacementStartIndex, replacementEndIndex, replacementSegmentCount int) (int, int, int, int) {
	//segmentCount := section.GetSegmentCount()
	if startIndex < 0 {
		startIndex = 0
	} else if startIndex > sourceCount {
		startIndex = sourceCount
	}
	if endIndex < startIndex {
		endIndex = startIndex
	} else if endIndex > sourceCount {
		endIndex = sourceCount
	}
	if replacementStartIndex < 0 {
		replacementStartIndex = 0
	} else if replacementStartIndex > replacementSegmentCount {
		replacementStartIndex = replacementSegmentCount
	}
	if replacementEndIndex < replacementStartIndex {
		replacementEndIndex = replacementStartIndex
	} else if replacementEndIndex > replacementSegmentCount {
		replacementEndIndex = replacementSegmentCount
	}
	return startIndex, endIndex, replacementStartIndex, replacementEndIndex
}

func (grouping *addressDivisionGroupingInternal) visitDivisions(target func(index int, div *AddressDivision) bool, targetLen int) (count int) {
	if grouping.hasNoDivisions() {
		return
	}
	count = grouping.GetDivisionCount()
	if count > targetLen {
		count = targetLen
	}
	for start := 0; start < count; start++ {
		if target(start, grouping.getDivision(start)) {
			break
		}
	}
	return
}

func (grouping *addressDivisionGroupingInternal) visitSubDivisions(start, end int, target func(index int, div *AddressDivision) (stop bool), targetLen int) (count int) {
	if grouping.hasNoDivisions() {
		return
	}
	targetIndex := 0
	start, end, targetIndex = adjust1To1Indices(start, end, grouping.GetDivisionCount(), targetIndex, targetLen)

	// now iterate start to end
	index := start
	for index < end {
		exitEarly := target(targetIndex, grouping.getDivision(index))
		index++
		if exitEarly {
			break
		}
		targetIndex++
	}
	return index - start
}

// copySubDivisions copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (grouping *addressDivisionGroupingInternal) copySubDivisions(start, end int, divs []*AddressDivision) (count int) {
	//return grouping.visitSubDivisions(start, end, func(index int, div *AddressDivision) bool { divs[index] = div; return false }, len(divs))
	//divsArray := grouping.divisions
	//if divsArray != nil {
	//	return divsArray.(standardDivArray).copySubDivisions(start, end, divs)
	//}
	divsArray := grouping.divisions
	if divsArray != nil {
		targetIndex := 0
		start, end, targetIndex = adjust1To1Indices(start, end, grouping.GetDivisionCount(), targetIndex, len(divs))
		//return copy(grouping.divs,divsArray[start:end])
		return divsArray.(standardDivArray).copySubDivisions(start, end, divs)
		//xxxx
	}
	return
}

// copyDivisions copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (grouping *addressDivisionGroupingInternal) copyDivisions(divs []*AddressDivision) (count int) {
	//return grouping.visitDivisions(func(index int, div *AddressDivision) bool { divs[index] = div; return false }, len(divs))
	divsArray := grouping.divisions
	if divsArray != nil {
		return divsArray.(standardDivArray).copyDivisions(divs)
	}
	return
}

func (grouping *addressDivisionGroupingInternal) getSubDivisions(start, end int) []*AddressDivision {
	divsArray := grouping.divisions
	if divsArray != nil {
		return divsArray.(standardDivArray).getSubDivisions(start, end)
	} else if start != 0 || end != 0 {
		panic("invalid subslice")
	}
	return make([]*AddressDivision, 0)
}

func (grouping *addressDivisionGroupingInternal) isAddressSection() bool {
	return grouping != nil && grouping.matchesAddrSectionType()
}

//func (grouping *addressDivisionGroupingInternal) isAddressSection() bool {
//	if grouping == nil {
//		return false
//	}
//	if grouping.matchesAddrSectionType() {
//		return true
//	}
//	var bitCount BitCount
//	count := grouping.GetDivisionCount()
//	// all divisions must be equal size and have an exact number of bytes
//	for i := 0; i < count; i++ {
//		div := grouping.getDivision(i)
//		if i == 0 {
//			bitCount = div.GetBitCount()
//			if bitCount%8 != 0 || bitCount > SegIntSize {
//				return false
//			}
//		} else if bitCount != div.GetBitCount() {
//			return false
//		}
//	}
//	return true
//}

func (grouping *addressDivisionGroupingInternal) CompareSize(other AddressDivisionSeries) int { // the GetCount() is optimized which is why we do not defer to the method in addressDivisionGroupingBase
	if !grouping.IsMultiple() {
		if other.IsMultiple() {
			return -1
		}
		return 0
	}
	if !other.IsMultiple() {
		return 1
	}
	return grouping.GetCount().CmpAbs(other.GetCount())
}

func (grouping *addressDivisionGroupingInternal) GetCount() *big.Int {
	if !grouping.IsMultiple() {
		return bigOne()
	} else if section := grouping.toAddressSection(); section != nil {
		return section.GetCount()
	}
	return grouping.addressDivisionGroupingBase.GetCount()
}

func (grouping *addressDivisionGroupingInternal) GetPrefixCount() *big.Int {
	if section := grouping.toAddressSection(); section != nil {
		return section.GetPrefixCount()
	}
	return grouping.addressDivisionGroupingBase.GetPrefixCount()
}

func (grouping *addressDivisionGroupingInternal) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	if section := grouping.toAddressSection(); section != nil {
		return section.GetPrefixCountLen(prefixLen)
	}
	return grouping.addressDivisionGroupingBase.GetPrefixCountLen(prefixLen)
}

func (grouping *addressDivisionGroupingInternal) getDivisionStrings() []string {
	if grouping.hasNoDivisions() {
		return []string{}
	}
	result := make([]string, grouping.GetDivisionCount())
	for i := range result {
		result[i] = grouping.getDivision(i).String()
	}
	return result
}

func (grouping *addressDivisionGroupingInternal) getSegmentStrings() []string {
	if grouping.hasNoDivisions() {
		return []string{}
	}
	result := make([]string, grouping.GetDivisionCount())
	for i := range result {
		result[i] = grouping.getDivision(i).GetWildcardString()
	}
	return result
}

func (grouping *addressDivisionGroupingInternal) toAddressDivisionGrouping() *AddressDivisionGrouping {
	return (*AddressDivisionGrouping)(unsafe.Pointer(grouping))
}

func (grouping *addressDivisionGroupingInternal) toAddressSection() *AddressSection {
	return grouping.toAddressDivisionGrouping().ToAddressSection()
}

func (grouping *addressDivisionGroupingInternal) matchesIPv6AddressType() bool {
	return grouping.getAddrType().isIPv6() // no need to check segment count because addresses cannot be constructed with incorrect segment count
}

func (grouping *addressDivisionGroupingInternal) matchesIPv4AddressType() bool {
	return grouping.getAddrType().isIPv4() // no need to check segment count because addresses cannot be constructed with incorrect segment count
}

func (grouping *addressDivisionGroupingInternal) matchesIPAddressType() bool {
	return grouping.matchesIPSectionType() // no need to check segment count because addresses cannot be constructed with incorrect segment count (note the zero IPAddress has zero segments)
}

func (grouping *addressSectionInternal) matchesMACAddressType() bool {
	return grouping.getAddrType().isMAC()
}

func (grouping *addressDivisionGroupingInternal) matchesAddrSectionType() bool {
	return !grouping.getAddrType().isNil() || grouping.hasNoDivisions()
}

func (grouping *addressDivisionGroupingInternal) matchesIPv6SectionType() bool {
	addrType := grouping.getAddrType()
	return addrType.isIPv6() || (addrType.isNil() && grouping.hasNoDivisions())
}

func (grouping *addressDivisionGroupingInternal) matchesIPv6v4MixedGroupingType() bool {
	addrType := grouping.getAddrType()
	return addrType.isIPv6v4Mixed() || (addrType.isNil() && grouping.hasNoDivisions())
}

func (grouping *addressDivisionGroupingInternal) matchesIPv4SectionType() bool {
	addrType := grouping.getAddrType()
	return addrType.isIPv4() || (addrType.isNil() && grouping.hasNoDivisions())
}

func (grouping *addressDivisionGroupingInternal) matchesIPSectionType() bool {
	addrType := grouping.getAddrType()
	return addrType.isIP() || (addrType.isNil() && grouping.hasNoDivisions())
}

func (grouping *addressDivisionGroupingInternal) matchesMACSectionType() bool {
	addrType := grouping.getAddrType()
	return addrType.isMAC() || (addrType.isNil() && grouping.hasNoDivisions())
}

func (grouping *addressDivisionGroupingInternal) initDivs() *addressDivisionGroupingInternal {
	if grouping.divisions == nil {
		return &zeroSection.addressDivisionGroupingInternal
	}
	return grouping
}

func (grouping addressDivisionGroupingInternal) String() string {
	if sect := grouping.toAddressSection(); sect != nil {
		return sect.ToNormalizedString()
	}
	return fmt.Sprintf("%v", grouping.initDivs().divisions)
}

func (grouping *addressDivisionGroupingInternal) GetPrefixLen() PrefixLen {
	return grouping.prefixLength
}

func (grouping *addressDivisionGroupingInternal) IsPrefixed() bool {
	return grouping.prefixLength != nil
}

//TODO LATER eventually when supporting large divisions,
//might move containsPrefixBlock(prefixLen BitCount), containsSinglePrefixBlock(prefixLen BitCount),
// GetMinPrefixLenForBlock, and GetPrefixLenForSingleBlock into groupingBase code
// IsPrefixBlock, IsSinglePrefixBlock
// which looks straightforward since none deal with DivInt, instead they all call into divisionValues interface

func (grouping *addressDivisionGroupingInternal) ContainsPrefixBlock(prefixLen BitCount) bool {
	if section := grouping.toAddressSection(); section != nil {
		return section.ContainsPrefixBlock(prefixLen)
	}
	prefixLen = checkSubnet(grouping, prefixLen)
	divisionCount := grouping.GetDivisionCount()
	var prevBitCount BitCount
	for i := 0; i < divisionCount; i++ {
		division := grouping.getDivision(i)
		bitCount := division.GetBitCount()
		totalBitCount := bitCount + prevBitCount
		if prefixLen < totalBitCount {
			divPrefixLen := prefixLen - prevBitCount
			if !division.containsPrefixBlock(divPrefixLen) {
				return false
			}
			for i++; i < divisionCount; i++ {
				division = grouping.getDivision(i)
				if !division.IsFullRange() {
					return false
				}
			}
			return true
		}
		prevBitCount = totalBitCount
	}
	return true
}

func (grouping *addressDivisionGroupingInternal) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	prefixLen = checkSubnet(grouping, prefixLen)
	divisionCount := grouping.GetDivisionCount()
	var prevBitCount BitCount
	for i := 0; i < divisionCount; i++ {
		division := grouping.getDivision(i)
		bitCount := division.getBitCount()
		totalBitCount := bitCount + prevBitCount
		if prefixLen >= totalBitCount {
			if division.isMultiple() {
				return false
			}
		} else {
			divPrefixLen := prefixLen - prevBitCount
			if !division.ContainsSinglePrefixBlock(divPrefixLen) {
				return false
			}
			for i++; i < divisionCount; i++ {
				division = grouping.getDivision(i)
				if !division.IsFullRange() {
					return false
				}
			}
			return true
		}
		prevBitCount = totalBitCount
	}
	return true
}

func (grouping *addressDivisionGroupingInternal) IsPrefixBlock() bool { //Note for any given prefix length you can compare with GetMinPrefixLenForBlock
	prefLen := grouping.GetPrefixLen()
	return prefLen != nil && grouping.ContainsPrefixBlock(*prefLen)
}

func (grouping *addressDivisionGroupingInternal) IsSinglePrefixBlock() bool { //Note for any given prefix length you can compare with GetPrefixLenForSingleBlock
	calc := func() bool {
		prefLen := grouping.GetPrefixLen()
		return prefLen != nil && grouping.ContainsSinglePrefixBlock(*prefLen)
	}
	cache := grouping.cache
	if cache == nil {
		return calc()
	}
	res := cache.isSinglePrefixBlock
	if res == nil {
		if calc() {
			res = &trueVal

			// we can also set related cache fields
			pref := grouping.GetPrefixLen()
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.equivalentPrefix))
			atomic.StorePointer(dataLoc, unsafe.Pointer(pref))

			dataLoc = (*unsafe.Pointer)(unsafe.Pointer(&cache.minPrefix))
			atomic.StorePointer(dataLoc, unsafe.Pointer(pref))
		} else {
			res = &falseVal
		}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.isSinglePrefixBlock))
		atomic.StorePointer(dataLoc, unsafe.Pointer(res))
	}
	return *res
}

func (grouping *addressDivisionGroupingInternal) GetMinPrefixLenForBlock() BitCount {
	calc := func() BitCount {
		count := grouping.GetDivisionCount()
		totalPrefix := grouping.GetBitCount()
		for i := count - 1; i >= 0; i-- {
			div := grouping.getDivision(i)
			segBitCount := div.getBitCount()
			segPrefix := div.GetMinPrefixLenForBlock()
			if segPrefix == segBitCount {
				break
			} else {
				totalPrefix -= segBitCount
				if segPrefix != 0 {
					totalPrefix += segPrefix
					break
				}
			}
		}
		return totalPrefix
	}
	cache := grouping.cache
	if cache == nil {
		return calc()
	}
	res := cache.minPrefix
	if res == nil {
		val := calc()
		res = cacheBitCount(val)
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.minPrefix))
		atomic.StorePointer(dataLoc, unsafe.Pointer(res))
	}
	return *res
}

func (grouping *addressDivisionGroupingInternal) GetPrefixLenForSingleBlock() PrefixLen {
	calc := func() PrefixLen {
		count := grouping.GetDivisionCount()
		var totalPrefix BitCount
		for i := 0; i < count; i++ {
			div := grouping.getDivision(i)
			divPrefix := div.GetPrefixLenForSingleBlock()
			if divPrefix == nil {
				return nil
			}
			divPrefLen := *divPrefix
			totalPrefix += divPrefLen
			if divPrefLen < div.GetBitCount() {
				//remaining segments must be full range or we return nil
				for i++; i < count; i++ {
					laterDiv := grouping.getDivision(i)
					if !laterDiv.IsFullRange() {
						return nil
					}
				}
			}
		}
		return cacheBitCount(totalPrefix)
	}
	cache := grouping.cache
	if cache == nil {
		return calc()
	}
	res := cache.equivalentPrefix
	if res == nil {
		res = calc()
		if res == nil {
			res = noPrefix
			// we can also set related cache fields
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.isSinglePrefixBlock))
			atomic.StorePointer(dataLoc, unsafe.Pointer(&falseVal))
		} else {
			// we can also set related cache fields
			var isSingleBlock *bool
			if grouping.IsPrefixed() && PrefixEquals(res, grouping.GetPrefixLen()) {
				isSingleBlock = &trueVal
			} else {
				isSingleBlock = &falseVal
			}
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.isSinglePrefixBlock))
			atomic.StorePointer(dataLoc, unsafe.Pointer(isSingleBlock))

			dataLoc = (*unsafe.Pointer)(unsafe.Pointer(&cache.minPrefix))
			atomic.StorePointer(dataLoc, unsafe.Pointer(res))
		}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.equivalentPrefix))
		atomic.StorePointer(dataLoc, unsafe.Pointer(res))
	}
	if res == noPrefix {
		return nil
	}
	return res
}

func (grouping *addressDivisionGroupingInternal) GetValue() *big.Int {
	if grouping.hasNoDivisions() {
		return bigZero()
	}
	return bigZero().SetBytes(grouping.getBytes())
}

func (grouping *addressDivisionGroupingInternal) GetUpperValue() *big.Int {
	if grouping.hasNoDivisions() {
		return bigZero()
	}
	return bigZero().SetBytes(grouping.getUpperBytes())
}

func (grouping *addressDivisionGroupingInternal) CompareTo(item AddressItem) int {
	return CountComparator.Compare(grouping, item)
}

//func (grouping *addressDivisionGroupingInternal) Equals(other GenericGroupingType) bool { xxxx need subs to have this xxxx
//	// For an identity comparison need to access the *addressDivisionGroupingBase or something
//	//otherSection := other.to
//	//if section.toAddressSection() == otherSection {
//	//	return true
//	//}
//	if section := grouping.toAddressSection(); section != nil {
//		if otherGrp, ok := other.(StandardDivisionGroupingType); ok {
//			otherSect := otherGrp.ToAddressDivisionGrouping().ToAddressSection()
//			return otherSect != nil && section.EqualsSection(otherSect)
//		}
//		return false
//	}
//	matchesStructure, count := grouping.matchesTypeAndCount(other)
//	if !matchesStructure {
//		return false
//	} else {
//		for i := 0; i < count; i++ {
//			one := grouping.getDivision(i)
//			two := other.GetGenericDivision(i)
//			if !one.Equals(two) { //this checks the division types and also the bit counts
//				return false
//			}
//		}
//	}
//	return true
//}

func (grouping *addressDivisionGroupingInternal) GetBytes() []byte {
	if grouping.hasNoDivisions() {
		return emptyBytes
	}
	cached := grouping.getBytes()
	return cloneBytes(cached)
}

func (grouping *addressDivisionGroupingInternal) GetUpperBytes() []byte {
	if grouping.hasNoDivisions() {
		return emptyBytes
	}
	cached := grouping.getUpperBytes()
	return cloneBytes(cached)
}

// CopyBytes gets the value for the lowest address in the range represented by this address division grouping.
//
// If the value fits in the given slice, the same slice is returned with the value.
// Otherwise, a new slice is allocated and returned with the value.
//
// You can use getBitCount() to determine the required array length for the bytes.
func (grouping *addressDivisionGroupingInternal) CopyBytes(bytes []byte) []byte {
	if grouping.hasNoDivisions() {
		if bytes != nil {
			return bytes
		}
		return emptyBytes
	}
	return getBytesCopy(bytes, grouping.getBytes())
}

func (grouping *addressDivisionGroupingInternal) CopyUpperBytes(bytes []byte) []byte {
	if grouping.hasNoDivisions() {
		if bytes != nil {
			return bytes
		}
		return emptyBytes
	}
	return getBytesCopy(bytes, grouping.getUpperBytes())
}

func (grouping *addressDivisionGroupingInternal) getBytes() (bytes []byte) {
	bytes, _ = grouping.getCachedBytes(grouping.calcBytes)
	return
}

func (grouping *addressDivisionGroupingInternal) getUpperBytes() (bytes []byte) {
	_, bytes = grouping.getCachedBytes(grouping.calcBytes)
	return
}

func (grouping *addressDivisionGroupingInternal) calcBytes() (bytes, upperBytes []byte) {
	addrType := grouping.getAddrType()
	divisionCount := grouping.GetDivisionCount()
	isMultiple := grouping.IsMultiple()
	if addrType.isIPv4() || addrType.isMAC() {
		bytes = make([]byte, divisionCount)
		if isMultiple {
			upperBytes = make([]byte, divisionCount)
		} else {
			upperBytes = bytes
		}
		for i := 0; i < divisionCount; i++ {
			seg := grouping.getDivision(i).ToAddressSegment()
			bytes[i] = byte(seg.GetSegmentValue())
			if isMultiple {
				upperBytes[i] = byte(seg.GetUpperSegmentValue())
			}
		}
	} else if addrType.isIPv6() {
		byteCount := divisionCount << 1
		bytes = make([]byte, byteCount)
		if isMultiple {
			upperBytes = make([]byte, byteCount)
		} else {
			upperBytes = bytes
		}
		for i := 0; i < divisionCount; i++ {
			seg := grouping.getDivision(i).ToAddressSegment()
			byteIndex := i << 1
			val := seg.GetSegmentValue()
			bytes[byteIndex] = byte(val >> 8)
			var upperVal SegInt
			if isMultiple {
				upperVal = seg.GetUpperSegmentValue()
				upperBytes[byteIndex] = byte(upperVal >> 8)
			}
			nextByteIndex := byteIndex + 1
			bytes[nextByteIndex] = byte(val)
			if isMultiple {
				upperBytes[nextByteIndex] = byte(upperVal)
			}
		}
	} else {
		byteCount := grouping.GetByteCount()
		bytes = make([]byte, byteCount)
		if isMultiple {
			upperBytes = make([]byte, byteCount)
		} else {
			upperBytes = bytes
		}
		for k, byteIndex, bitIndex := divisionCount-1, byteCount-1, BitCount(8); k >= 0; k-- {
			div := grouping.getDivision(k)
			val := div.GetDivisionValue()
			var upperVal DivInt
			if isMultiple {
				upperVal = div.GetUpperDivisionValue()
			}
			divBits := div.GetBitCount()
			for divBits > 0 {
				rbi := 8 - bitIndex
				bytes[byteIndex] |= byte(val << uint(rbi))
				val >>= uint(bitIndex)
				if isMultiple {
					upperBytes[byteIndex] |= byte(upperVal << uint(rbi))
					upperVal >>= uint(bitIndex)
				}
				if divBits < bitIndex {
					bitIndex -= divBits
					break
				} else {
					divBits -= bitIndex
					bitIndex = 8
					byteIndex--
				}
			}
		}
	}
	return
}

// Returns whether the series represents a range of values that are sequential.
// Generally, this means that any division covering a range of values must be followed by divisions that are full range, covering all values.
func (grouping *addressDivisionGroupingInternal) IsSequential() bool {
	count := grouping.GetDivisionCount()
	if count > 1 {
		for i := 0; i < count; i++ {
			if grouping.getDivision(i).IsMultiple() {
				for i++; i < count; i++ {
					if !grouping.getDivision(i).IsFullRange() {
						return false
					}
				}
				return true
			}
		}
	}
	return true
}

func (grouping *addressDivisionGroupingInternal) Equals(other GenericGroupingType) bool {
	// For an identity comparison need to access the *addressDivisionGroupingBase or something
	//otherSection := other.to
	//if section.toAddressSection() == otherSection {
	//	return true
	//}
	if section := grouping.toAddressSection(); section != nil {
		if otherGrouping, ok := other.(StandardDivisionGroupingType); ok {
			if otherSection := otherGrouping.ToAddressDivisionGrouping().ToAddressSection(); otherSection != nil {
				return section.EqualsSection(otherSection)
			}
		}
		return false
	}
	matchesStructure, count := grouping.matchesTypeAndCount(other)
	if !matchesStructure {
		return false
	} else {
		for i := 0; i < count; i++ {
			one := grouping.getDivision(i)
			two := other.GetGenericDivision(i)
			if !one.Equals(two) { //this checks the division types and also the bit counts
				return false
			}
		}
	}
	return true
}

//protected static interface GroupingCreator<S extends AddressDivisionBase> {
//		S createDivision(long value, long upperValue, int bitCount, int radix);
//	}

func (grouping *addressDivisionGroupingInternal) createNewDivisions(bitsPerDigit BitCount) []*AddressDivision {
	return grouping.createNewPrefixedDivisions(bitsPerDigit, nil)
}

//protected static interface PrefixedGroupingCreator<S extends AddressDivisionBase> {
//	S createDivision(long value, long upperValue, int bitCount, int radix, IPAddressNetwork<?, ?, ?, ?, ?> network, Integer prefixLength);
//}

//TODO this should return an error in the usual case where we divide a ranged segment and the lower part is not full range, but right now this is fine because we never call with ranged segments
// If two multi divisions are in sequence and the second is not full range, then they must originate from separate segments
// so, when you create a division you know the current segment index, now you keep track of the segment index for the last division,
// and you can do this check when creating each division
// Additionally, you need another check, when you are handling the case where the division has more bits left than the segment,
// then you must check that the existing division values are not multi, OR the new segment values are full range

func (grouping *addressDivisionGroupingInternal) createNewPrefixedDivisions(bitsPerDigit BitCount, networkPrefixLength PrefixLen) []*AddressDivision {
	//if(bitsPerDigit >= Integer.SIZE) {
	//	//keep in mind once you hit 5 bits per digit, radix 32, you need 32 different digits, and there are only 26 alphabet characters and 10 digit chars, so 36
	//	//so once you get higher than that, you need a new character set.
	//	//AddressLargeDivision allows all the way up to base 85
	//	throw new AddressValueException(bitsPerDigit);
	//}
	bitCount := grouping.GetBitCount()
	//List<Integer> bitDivs = new ArrayList<Integer>(bitsPerDigit);
	var bitDivs []BitCount

	// here we divide into divisions, each with an exact number of digits.
	// Each digit takes 3 bits.  So the division bit-sizes are a multiple of 3 until the last one.

	//ipv6 octal:
	//seg bit counts: 63, 63, 2
	//ipv4 octal:
	//seg bit counts: 30, 2

	largestBitCount := BitCount(64) // uint64, size of DivInt

	//int largestBitCount = Long.SIZE - 1;
	largestBitCount -= largestBitCount % bitsPerDigit // round off to a multiple of 3 bits
	for {
		if bitCount <= largestBitCount {
			mod := bitCount % bitsPerDigit
			secondLast := bitCount - mod
			if secondLast > 0 {
				//bitDivs.add(cacheBits(secondLast));
				bitDivs = append(bitDivs, secondLast)
			}
			if mod > 0 {
				bitDivs = append(bitDivs, mod)
				//bitDivs.add(cacheBits(mod));
			}
			break
		} else {
			bitCount -= largestBitCount
			bitDivs = append(bitDivs, largestBitCount)
			//bitDivs.add(cacheBits(largestBitCount));
		}
	}

	// at this point bitDivs has our division sizes

	divCount := len(bitDivs)
	divs := make([]*AddressDivision, divCount)
	//S divs[] = groupingArrayCreator.apply(divCount);
	currentSegmentIndex := 0
	seg := grouping.getDivision(currentSegmentIndex)
	segLowerVal := seg.GetDivisionValue()
	segUpperVal := seg.GetUpperDivisionValue()
	segBits := seg.GetBitCount()
	bitsSoFar := BitCount(0)

	// 2 to the x is all ones shift left x, then not, then add 1
	// so, for x == 1, 1111111 -> 1111110 -> 0000001 -> 0000010
	radix := ^(^(0) << uint(bitsPerDigit)) + 1
	//int radix = AddressDivision.getRadixPower(BigInteger.valueOf(2), bitsPerDigit).intValue();
	//fill up our new divisions, one by one
	for i := divCount - 1; i >= 0; i-- {

		//int originalDivBitSize, divBitSize;
		divBitSize := bitDivs[i]
		originalDivBitSize := divBitSize
		//long divLowerValue, divUpperValue;
		//divLowerValue = divUpperValue = 0;
		var divLowerValue, divUpperValue uint64
		for {
			if segBits >= divBitSize { // this segment fills the remainder of this division
				diff := uint(segBits - divBitSize)
				//udiff := uint(diff);
				divLowerValue |= segLowerVal >> diff
				shift := ^(^uint64(0) << diff)
				segLowerVal &= shift
				divUpperValue |= segUpperVal >> diff
				segUpperVal &= shift
				segBits = BitCount(diff)
				var segPrefixBits PrefixLen
				if networkPrefixLength != nil {
					segPrefixBits = getDivisionPrefixLength(originalDivBitSize, *networkPrefixLength-bitsSoFar)
				}
				//Integer segPrefixBits = networkPrefixLength == null ? null : getSegmentPrefixLength(originalDivBitSize, networkPrefixLength - bitsSoFar);
				div := NewRangePrefixDivision(divLowerValue, divUpperValue, segPrefixBits, originalDivBitSize, radix)
				//S div = groupingCreator.createDivision(divLowerValue, divUpperValue, originalDivBitSize, radix, network, segPrefixBits);
				divs[divCount-i-1] = div
				if segBits == 0 && i > 0 {
					//get next seg
					currentSegmentIndex++
					seg = grouping.getDivision(currentSegmentIndex)
					segLowerVal = seg.getDivisionValue()
					segUpperVal = seg.getUpperDivisionValue()
					segBits = seg.getBitCount()
				}
				break
			} else {
				diff := uint(divBitSize - segBits)
				divLowerValue |= segLowerVal << diff
				divUpperValue |= segUpperVal << diff
				divBitSize = BitCount(diff)

				//get next seg
				currentSegmentIndex++
				seg = grouping.getDivision(currentSegmentIndex)
				segLowerVal = seg.getDivisionValue()
				segUpperVal = seg.getUpperDivisionValue()
				segBits = seg.getBitCount()
			}
		}
		bitsSoFar += originalDivBitSize
	}
	return divs
}

type AddressDivisionGrouping struct {
	addressDivisionGroupingInternal
}

// copySubDivisions copies the existing divisions from the given start index until but not including the division at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (grouping *AddressDivisionGrouping) CopySubDivisions(start, end int, divs []*AddressDivision) (count int) {
	return grouping.copySubDivisions(start, end, divs)
}

// CopyDivisions copies the existing divisions from the given start index until but not including the division at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (grouping *AddressDivisionGrouping) CopyDivisions(divs []*AddressDivision) (count int) {
	return grouping.copyDivisions(divs)
}

func (grouping *AddressDivisionGrouping) GetDivisionStrings() []string {
	return grouping.getDivisionStrings()
}

func (grouping *AddressDivisionGrouping) IsAddressSection() bool {
	return grouping != nil && grouping.isAddressSection()
}

func (grouping *AddressDivisionGrouping) IsIPAddressSection() bool {
	return grouping.ToAddressSection().IsIPAddressSection()
}

func (grouping *AddressDivisionGrouping) IsIPv4AddressSection() bool {
	return grouping.ToAddressSection().IsIPv4AddressSection()
}

func (grouping *AddressDivisionGrouping) IsIPv6AddressSection() bool {
	return grouping.ToAddressSection().IsIPv6AddressSection()
}

func (grouping *AddressDivisionGrouping) IsIPv6v4MixedAddressGrouping() bool {
	return grouping.matchesIPv6v4MixedGroupingType()
}

func (grouping *AddressDivisionGrouping) IsMACAddressSection() bool {
	return grouping.ToAddressSection().IsMACAddressSection()
}

// ToAddressSection converts to an address section.
// If the conversion cannot happen due to division size or count, the result will be the zero value.
func (grouping *AddressDivisionGrouping) ToAddressSection() *AddressSection {
	if grouping == nil || !grouping.isAddressSection() {
		return nil
	}
	return (*AddressSection)(unsafe.Pointer(grouping))
}

func (grouping *AddressDivisionGrouping) ToIPv4v6MixedAddressGrouping() *IPv6v4MixedAddressGrouping {
	if grouping.matchesIPv6v4MixedGroupingType() {
		return (*IPv6v4MixedAddressGrouping)(grouping)
	}
	return nil
}

func (grouping *AddressDivisionGrouping) ToIPAddressSection() *IPAddressSection {
	return grouping.ToAddressSection().ToIPAddressSection()
}

func (grouping *AddressDivisionGrouping) ToIPv6AddressSection() *IPv6AddressSection {
	return grouping.ToAddressSection().ToIPv6AddressSection()
}

func (grouping *AddressDivisionGrouping) ToIPv4AddressSection() *IPv4AddressSection {
	return grouping.ToAddressSection().ToIPv4AddressSection()
}

func (grouping *AddressDivisionGrouping) ToMACAddressSection() *MACAddressSection {
	return grouping.ToAddressSection().ToMACAddressSection()
}

func (grouping *AddressDivisionGrouping) ToAddressDivisionGrouping() *AddressDivisionGrouping {
	return grouping
}

func (grouping *AddressDivisionGrouping) GetDivision(index int) *AddressDivision {
	return grouping.getDivision(index)
}
