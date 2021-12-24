package ipaddr

import (
	"fmt"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrerr"
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
	result.isMult = isMultiple
	return result
}

func createInitializedGrouping(divs []*AddressDivision, prefixLength PrefixLen) *AddressDivisionGrouping {
	result := createGrouping(divs, prefixLength, zeroType)
	result.initMultiple() // assigns isMult
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
		if div.isMultiple() {
			grouping.isMult = true
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

//func (grouping *addressDivisionGroupingInternal) CompareSize(other AddressDivisionSeries) int { // the getCount() is optimized which is why we do not defer to the method in addressDivisionGroupingBase
func (grouping *addressDivisionGroupingInternal) compareSize(other StandardDivGroupingType) int { // the getCount() is optimized which is why we do not defer to the method in addressDivisionGroupingBase
	if other == nil || other.ToDivGrouping() == nil {
		// our size is 1 or greater, other 0
		return 1
	}
	if !grouping.isMultiple() {
		if other.IsMultiple() {
			return -1
		}
		return 0
	} else if !other.IsMultiple() {
		return 1
	}
	return grouping.getCount().CmpAbs(other.GetCount())
}

func (grouping *addressDivisionGroupingInternal) getCount() *big.Int {
	if !grouping.isMultiple() {
		return bigOne()
	} else if section := grouping.toAddressSection(); section != nil {
		return section.GetCount()
	}
	return grouping.addressDivisionGroupingBase.getCount()
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
	return grouping.toAddressDivisionGrouping().ToSectionBase()
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

// The zero grouping, produced by zero sections like IPv4AddressSection{} or AddressDivisionGrouping{}, can represent a zero-length section of any address type,
// It is not considered equal to constructions of specific zero length sections of groupings like NewIPv4Section(nil) which can only represent a zero-length section of a single address type.
func (grouping *addressDivisionGroupingInternal) matchesZeroGrouping() bool {
	addrType := grouping.getAddrType()
	return addrType.isNil() && grouping.hasNoDivisions()
}

func (grouping *addressDivisionGroupingInternal) matchesAddrSectionType() bool {
	addrType := grouping.getAddrType()
	// because there are no init() conversions for IPv6/IPV4/MAC sections, a zero-valued IPv6/IPV4/MAC or zero IP section has addr type nil
	return addrType.isIP() || addrType.isMAC() || grouping.matchesZeroGrouping()
}

func (grouping *addressDivisionGroupingInternal) matchesIPv6SectionType() bool {
	// because there are no init() conversions for IPv6 sections, a zero-valued IPV6 section has addr type nil
	return grouping.getAddrType().isIPv6() || grouping.matchesZeroGrouping()
}

func (grouping *addressDivisionGroupingInternal) matchesIPv6v4MixedGroupingType() bool {
	// because there are no init() conversions for IPv6v4MixedGrouping groupings, a zero-valued IPv6v4MixedGrouping has addr type nil
	return grouping.getAddrType().isIPv6v4Mixed() || grouping.matchesZeroGrouping()
}

func (grouping *addressDivisionGroupingInternal) matchesIPv4SectionType() bool {
	// because there are no init() conversions for IPV4 sections, a zero-valued IPV4 section has addr type nil
	return grouping.getAddrType().isIPv4() || grouping.matchesZeroGrouping()
}

func (grouping *addressDivisionGroupingInternal) matchesIPSectionType() bool {
	// because there are no init() conversions for IPv6 or IPV4 sections, a zero-valued IPv4, IPv6 or IP section has addr type nil
	return grouping.getAddrType().isIP() || grouping.matchesZeroGrouping()
}

func (grouping *addressDivisionGroupingInternal) matchesMACSectionType() bool {
	// because there are no init() conversions for MAC sections, a zero-valued MAC section has addr type nil
	return grouping.getAddrType().isMAC() || grouping.matchesZeroGrouping()
}

// Format implements fmt.Formatter. It accepts the formats
// 'v' for the default address and section format (either the normalized or canonical string),
// 's' (string) for the same,
// 'b' (binary), 'o' (octal with 0 prefix), 'O' (octal with 0o prefix),
// 'd' (decimal), 'x' (lowercase hexadecimal), and
// 'X' (uppercase hexadecimal).
// Also supported are some of fmt's format flags for integral types.
// Sign control is not supported since addresses and sections are never negative.
// '#' for alternate format is supported, which is leading zero in octal and for hexadecimal,
// a leading "0x" or "0X" for "%#x" and "%#X" respectively,
// Also supported when not using 's' is specification of minimum digits precision, output field
// width, space or zero padding, and '-' for left or right justification.
func (grouping addressDivisionGroupingInternal) Format(state fmt.State, verb rune) {
	if sect := grouping.toAddressSection(); sect != nil {
		sect.Format(state, verb)
		return
	}
	// divisions are printed like slices of *AddressDivision (which are Stringers) with division separated by spaces and enclosed in square brackets,
	// sections are printed like addresses with segments separated by segment separators
	grouping.defaultFormat(state, verb)
}

func (grouping addressDivisionGroupingInternal) defaultFormat(state fmt.State, verb rune) {
	s := flagsFromState(state, verb)
	state.Write([]byte(fmt.Sprintf(s, grouping.initDivs().divisions.(standardDivArray).divisions)))
}

func (grouping *addressDivisionGroupingInternal) toString() string {
	if sect := grouping.toAddressSection(); sect != nil {
		return sect.ToNormalizedString()
	}
	return fmt.Sprintf("%v", grouping.initDivs().divisions.(standardDivArray).divisions)
}

func (grouping *addressDivisionGroupingInternal) initDivs() *addressDivisionGroupingInternal {
	if grouping.divisions == nil {
		return &zeroSection.addressDivisionGroupingInternal
	}
	return grouping
}

func (grouping *addressDivisionGroupingInternal) GetPrefixLen() PrefixLen {
	return grouping.prefixLength
}

func (grouping *addressDivisionGroupingInternal) isPrefixed() bool {
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
	prefixLen = checkSubnet(grouping.toAddressDivisionGrouping(), prefixLen)
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
	prefixLen = checkSubnet(grouping.toAddressDivisionGrouping(), prefixLen)
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
	return prefLen != nil && grouping.ContainsPrefixBlock(prefLen.bitCount())
}

func (grouping *addressDivisionGroupingInternal) IsSinglePrefixBlock() bool { //Note for any given prefix length you can compare with GetPrefixLenForSingleBlock
	calc := func() bool {
		prefLen := grouping.GetPrefixLen()
		return prefLen != nil && grouping.ContainsSinglePrefixBlock(prefLen.bitCount())
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
	return res.bitCount()
}

func (grouping *addressDivisionGroupingInternal) GetPrefixLenForSingleBlock() PrefixLen {
	calc := func() *PrefixLen {
		count := grouping.GetDivisionCount()
		var totalPrefix BitCount
		for i := 0; i < count; i++ {
			div := grouping.getDivision(i)
			divPrefix := div.GetPrefixLenForSingleBlock()
			if divPrefix == nil {
				return cacheNilPrefix()
			}
			divPrefLen := divPrefix.bitCount()
			totalPrefix += divPrefLen
			if divPrefLen < div.GetBitCount() {
				//remaining segments must be full range or we return nil
				for i++; i < count; i++ {
					laterDiv := grouping.getDivision(i)
					if !laterDiv.IsFullRange() {
						return cacheNilPrefix()
					}
				}
			}
		}
		return cachePrefix(totalPrefix)
	}
	cache := grouping.cache
	if cache == nil {
		return *calc()
	}
	res := cache.equivalentPrefix
	if res == nil {
		res = calc()
		if *res == nil {
			// we can also set related cache fields
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.isSinglePrefixBlock))
			atomic.StorePointer(dataLoc, unsafe.Pointer(&falseVal))
		} else {
			// we can also set related cache fields
			var isSingleBlock *bool
			if grouping.isPrefixed() && (*res).Equal(grouping.GetPrefixLen()) {
				isSingleBlock = &trueVal
			} else {
				isSingleBlock = &falseVal
			}
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.isSinglePrefixBlock))
			atomic.StorePointer(dataLoc, unsafe.Pointer(isSingleBlock))

			dataLoc = (*unsafe.Pointer)(unsafe.Pointer(&cache.minPrefix))
			atomic.StorePointer(dataLoc, unsafe.Pointer(*res))
		}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.equivalentPrefix))
		atomic.StorePointer(dataLoc, unsafe.Pointer(res))
	}
	return *res
	//if res == noPrefix {
	//	return nil
	//}
	//return res
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

//func (grouping *addressDivisionGroupingInternal) Compare(item AddressItem) int {
//	xxx lowercase it xxxx
//	return CountComparator.Compare(grouping.toAddressDivisionGrouping(), item)
//}

//func (grouping *addressDivisionGroupingInternal) Equal(other GenericGroupingType) bool { xxxx need subs to have this xxxx
//	// For an identity comparison need to access the *addressDivisionGroupingBase or something
//	//otherSection := other.to
//	//if section.toAddressSection() == otherSection {
//	//	return true
//	//}
//	if section := grouping.toAddressSection(); section != nil {
//		if otherGrp, ok := other.(StandardDivGroupingType); ok {
//			otherSect := otherGrp.ToDivGrouping().ToSectionBase()
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
//			if !one.Equal(two) { //this checks the division types and also the bit counts
//				return false
//			}
//		}
//	}
//	return true
//}

func (grouping *addressDivisionGroupingInternal) Bytes() []byte {
	if grouping.hasNoDivisions() {
		return emptyBytes
	}
	cached := grouping.getBytes()
	return cloneBytes(cached)
}

func (grouping *addressDivisionGroupingInternal) UpperBytes() []byte {
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
	isMultiple := grouping.isMultiple()
	if addrType.isIPv4() || addrType.isMAC() {
		bytes = make([]byte, divisionCount)
		if isMultiple {
			upperBytes = make([]byte, divisionCount)
		} else {
			upperBytes = bytes
		}
		for i := 0; i < divisionCount; i++ {
			seg := grouping.getDivision(i).ToSegmentBase()
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
			seg := grouping.getDivision(i).ToSegmentBase()
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
			if grouping.getDivision(i).isMultiple() {
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

//func (grouping *addressDivisionGroupingInternal) Equal(other GenericGroupingType) bool {
//	// For an identity comparison need to access the *addressDivisionGroupingBase or something
//	//otherSection := other.to
//	//if section.toAddressSection() == otherSection {
//	//	return true
//	//}
//	if section := grouping.toAddressSection(); section != nil {
//		if otherGrouping, ok := other.(StandardDivGroupingType); ok {
//			if otherSection := otherGrouping.ToDivGrouping().ToSectionBase(); otherSection != nil {
//				return section.EqualsSection(otherSection)
//			}
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
//			if !one.Equal(two) { //this checks the division types and also the bit counts
//				return false
//			}
//		}
//	}
//	return true
//}

//protected static interface GroupingCreator<S extends AddressDivisionBase> {
//		S createDivision(long value, long upperValue, int bitCount, int radix);
//	}

func (grouping *addressDivisionGroupingInternal) createNewDivisions(bitsPerDigit BitCount) ([]*AddressDivision, addrerr.IncompatibleAddressError) {
	return grouping.createNewPrefixedDivisions(bitsPerDigit, nil)
}

//protected static interface PrefixedGroupingCreator<S extends AddressDivisionBase> {
//	S createDivision(long value, long upperValue, int bitCount, int radix, IPAddressNetwork<?, ?, ?, ?, ?> network, Integer prefixLength);
//}

func (grouping *addressDivisionGroupingInternal) createNewPrefixedDivisions(bitsPerDigit BitCount, networkPrefixLength PrefixLen) ([]*AddressDivision, addrerr.IncompatibleAddressError) {
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
	if divCount > 0 {
		//S divs[] = groupingArrayCreator.apply(divCount);
		currentSegmentIndex := 0
		seg := grouping.getDivision(currentSegmentIndex)
		segLowerVal := seg.GetDivisionValue()
		segUpperVal := seg.GetUpperDivisionValue()
		segBits := seg.GetBitCount()
		bitsSoFar := BitCount(0)

		// 2 to the x is all ones shift left x, then not, then add 1
		// so, for x == 1, 1111111 -> 1111110 -> 0000001 -> 0000010
		//radix := ^(^(0) << uint(bitsPerDigit)) + 1

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
					segBits = BitCount(diff)
					//udiff := uint(diff);
					segL := segLowerVal >> diff
					segU := segUpperVal >> diff

					// if the division upper bits are multiple, then the lower bits inserted must be full range
					if divLowerValue != divUpperValue {
						if segL != 0 || segU != ^(^uint64(0)<<uint(divBitSize)) {
							return nil, &incompatibleAddressError{addressError: addressError{key: "ipaddress.error.invalid.joined.ranges"}}
						}
					}

					divLowerValue |= segL
					divUpperValue |= segU

					shift := ^(^uint64(0) << diff)
					segLowerVal &= shift
					segUpperVal &= shift

					// if a segment's bits are split into two divisions, and the bits going into the first division are multi-valued,
					// then the bits going into the second division must be full range
					if segL != segU {
						if segLowerVal != 0 || segUpperVal != ^(^uint64(0)<<uint(segBits)) {
							return nil, &incompatibleAddressError{addressError: addressError{key: "ipaddress.error.invalid.joined.ranges"}}
						}
					}

					var segPrefixBits PrefixLen
					if networkPrefixLength != nil {
						segPrefixBits = getDivisionPrefixLength(originalDivBitSize, networkPrefixLength.bitCount()-bitsSoFar)
					}
					//Integer segPrefixBits = networkPrefixLength == null ? null : getSegmentPrefixLength(originalDivBitSize, networkPrefixLength - bitsSoFar);
					div := NewRangePrefixDivision(divLowerValue, divUpperValue, segPrefixBits, originalDivBitSize)
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
					// if the division upper bits are multiple, then the lower bits inserted must be full range
					if divLowerValue != divUpperValue {
						if segLowerVal != 0 || segUpperVal != ^(^uint64(0)<<uint(segBits)) {
							return nil, &incompatibleAddressError{addressError: addressError{key: "ipaddress.error.invalid.joined.ranges"}}
						}
					}
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
	}
	return divs, nil
}

type AddressDivisionGrouping struct {
	addressDivisionGroupingInternal
}

func (grouping *AddressDivisionGrouping) Compare(item AddressItem) int {
	return CountComparator.Compare(grouping, item)
}

func (grouping *AddressDivisionGrouping) CompareSize(other StandardDivGroupingType) int {
	if grouping == nil {
		if other != nil && other.ToDivGrouping() != nil {
			// we have size 0, other has size >= 1
			return -1
		}
		return 0
	}
	return grouping.compareSize(other)
}

func (grouping *AddressDivisionGrouping) GetCount() *big.Int {
	if grouping == nil {
		return bigZero()
	}
	return grouping.getCount()
}

func (grouping *AddressDivisionGrouping) IsMultiple() bool {
	return grouping != nil && grouping.isMultiple()
}

func (grouping *AddressDivisionGrouping) IsPrefixed() bool {
	if grouping == nil {
		return false
	}
	return grouping.isPrefixed()
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
	if grouping == nil {
		return nil
	}
	return grouping.getDivisionStrings()
}

// The zero grouping, produced by zero sections like IPv4AddressSection{} or AddressDivisionGrouping{}, can represent a zero-length section of any address type,
// It is not considered equal to constructions of specific zero length sections of groupings like NewIPv4Section(nil) which can only represent a zero-length section of a sinle address type.
func (grouping *AddressDivisionGrouping) IsZeroGrouping() bool {
	return grouping != nil && grouping.matchesZeroGrouping()
}

func (grouping *AddressDivisionGrouping) IsSectionBase() bool {
	return grouping != nil && grouping.isAddressSection()
}

func (grouping *AddressDivisionGrouping) IsIP() bool {
	return grouping.ToSectionBase().IsIP()
}

func (grouping *AddressDivisionGrouping) IsIPv4() bool {
	return grouping.ToSectionBase().IsIPv4()
}

func (grouping *AddressDivisionGrouping) IsIPv6() bool {
	return grouping.ToSectionBase().IsIPv6()
}

func (grouping *AddressDivisionGrouping) IsMixedIPv6v4() bool {
	return grouping != nil && grouping.matchesIPv6v4MixedGroupingType()
}

func (grouping *AddressDivisionGrouping) IsMAC() bool {
	return grouping.ToSectionBase().IsMAC()
}

// ToSectionBase converts to an address section.
// If the conversion cannot happen due to division size or count, the result will be the zero value.
func (grouping *AddressDivisionGrouping) ToSectionBase() *AddressSection {
	if grouping == nil || !grouping.isAddressSection() {
		return nil
	}
	return (*AddressSection)(unsafe.Pointer(grouping))
}

func (grouping *AddressDivisionGrouping) ToMixedIPv6v4() *IPv6v4MixedAddressGrouping {
	if grouping.matchesIPv6v4MixedGroupingType() {
		return (*IPv6v4MixedAddressGrouping)(grouping)
	}
	return nil
}

func (grouping *AddressDivisionGrouping) ToIP() *IPAddressSection {
	return grouping.ToSectionBase().ToIP()
}

func (grouping *AddressDivisionGrouping) ToIPv6() *IPv6AddressSection {
	return grouping.ToSectionBase().ToIPv6()
}

func (grouping *AddressDivisionGrouping) ToIPv4() *IPv4AddressSection {
	return grouping.ToSectionBase().ToIPv4()
}

func (grouping *AddressDivisionGrouping) ToMAC() *MACAddressSection {
	return grouping.ToSectionBase().ToMAC()
}

func (grouping *AddressDivisionGrouping) ToDivGrouping() *AddressDivisionGrouping {
	return grouping
}

func (grouping *AddressDivisionGrouping) GetDivision(index int) *AddressDivision {
	return grouping.getDivision(index)
}

func (grouping *AddressDivisionGrouping) String() string {
	if grouping == nil {
		return nilString()
	}
	return grouping.toString()
}
