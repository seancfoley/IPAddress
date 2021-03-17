package ipaddr

import (
	"fmt"
	"math/big"
	"unsafe"
)

var zeroSection = createSection(zeroDivs, nil, zeroType, 0)

func createSection(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType, startIndex uint8) *AddressSection {
	return &AddressSection{
		addressSectionInternal{
			addressDivisionGroupingInternal{
				addressDivisionGroupingBase: addressDivisionGroupingBase{
					divisions:    standardDivArray{segments},
					prefixLength: prefixLength,
					addrType:     addrType,
					cache:        &valueCache{},
				},
				addressSegmentIndex: startIndex,
			},
		},
	}
}

func createMultipleSection(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType, startIndex uint8, isMultiple bool) *AddressSection {
	result := createSection(segments, prefixLength, addrType, startIndex)
	result.isMultiple = isMultiple
	return result
}

func createInitializedSection(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType, startIndex uint8) *AddressSection {
	result := createSection(segments, prefixLength, addrType, startIndex)
	result.init() // assigns isMultiple
	return result
}

/*
// TODO MAC will need something like this when calculating prefix length on creation
//func (grouping *addressDivisionGroupingInternal) getPrefixLengthCacheLocked() PrefixLen {
//		count := grouping.getDivisionCount()
//		bitsSoFar, prefixBits := BitCount(0), BitCount(0)
//		hasPrefix := false
//		for i := 0; i < count; i++ {
//			div := grouping.getDivision(i)
//			divPrefLen := div.getDivisionPrefixLength() //TODO for MAC this needs to be changed to getMinPrefixLengthForBlock (optimize it to check for full range or single value first )
//			if hasPrefix = divPrefLen != nil; hasPrefix {
//				divPrefBits := *divPrefLen
//				if !hasPrefix || divPrefBits != 0 {
//					prefixBits = bitsSoFar + divPrefBits
//				}
//				if grouping.addrType.alignsPrefix() {
//					break
//				}
//			}
//			bitsSoFar += div.getBitCount()
//		}
//		if hasPrefix {
//			res := &prefixBits
//			prefLen.value = res
//		}
//}
*/

//////////////////////////////////////////////////////////////////
//
//
//
type addressSectionInternal struct {
	addressDivisionGroupingInternal
}

func (section *addressSectionInternal) toAddressSection() *AddressSection {
	return (*AddressSection)(unsafe.Pointer(section))
}

func (section *addressSectionInternal) ToAddressDivisionGrouping() *AddressDivisionGrouping {
	return (*AddressDivisionGrouping)(unsafe.Pointer(section))
}

// error returned for nil sements, or inconsistent prefixes
func (section *addressSectionInternal) init() error {
	segCount := section.GetSegmentCount()
	if segCount != 0 {
		var previousSegmentPrefix PrefixLen
		isMultiple := false
		bitsPerSegment := section.GetBitsPerSegment()
		for i := 0; i < segCount; i++ {
			div := section.getDivision(i)
			if div == nil {
				return &addressException{"ipaddress.error.null.segment"}
			}
			// unnecessary since we can control the division type
			// new ipv4/6 sections are created from ipv4/6segment while derived sections come from existing segments
			// in all cases, no way to insert mimatched divisions
			//else if section.getDivision(i).getBitCount() != bitsPerSegment {
			//	return &addressException{"ipaddress.error.mismatched.bit.size"}
			//}

			segment := section.GetSegment(i)
			if !isMultiple && segment.IsMultiple() {
				isMultiple = true
				section.isMultiple = true
			}

			//Calculate the segment-level prefix
			//
			//Across an address prefixes are:
			//IPv6: (null):...:(null):(1 to 16):(0):...:(0)
			//or IPv4: ...(null).(1 to 8).(0)...
			//For MAC, all segs have nil prefix since prefix is not segment-level
			//For MAC, prefixes must be derived in other ways, not from individual segment prefix values,
			// either using
			segPrefix := segment.getDivisionPrefixLength()
			if previousSegmentPrefix == nil {
				if segPrefix != nil {
					section.prefixLength = getNetworkPrefixLength(bitsPerSegment, *segPrefix, i)
				}
			} else if segPrefix == nil || *segPrefix != 0 {
				return &inconsistentPrefixException{str: fmt.Sprintf("%v %v %v", section.GetSegment(i-1), segment, segPrefix), key: "ipaddress.error.inconsistent.prefixes"}
			}
			previousSegmentPrefix = segPrefix
		}
	}
	return nil
}

func (section *addressSectionInternal) GetBitsPerSegment() BitCount {
	if section.GetDivisionCount() == 0 {
		return 0
	}
	return section.getDivision(0).GetBitCount()
}

func (section *addressSectionInternal) GetBytesPerSegment() int {
	if section.GetDivisionCount() == 0 {
		return 0
	}
	return section.getDivision(0).GetByteCount()
}

func (section *addressSectionInternal) GetSegment(index int) *AddressSegment {
	return section.getDivision(index).ToAddressSegment()
}

func (section *addressSectionInternal) GetSegmentCount() int {
	return section.GetDivisionCount()
}

func (section *addressSectionInternal) GetBitCount() BitCount {
	divLen := section.GetDivisionCount()
	if divLen == 0 {
		return 0
	}
	return getSegmentsBitCount(section.getDivision(0).GetBitCount(), section.GetSegmentCount())
}

func (section *addressSectionInternal) GetByteCount() int {
	return int((section.GetBitCount() + 7) >> 3)
}

func (section *addressSectionInternal) GetMaxSegmentValue() SegInt {
	divLen := section.GetDivisionCount()
	if divLen == 0 {
		return 0
	}
	return section.GetSegment(0).GetMaxValue()
}

// Gets the subsection from the series starting from the given index and ending just before the give endIndex
// The first segment is at index 0.
func (section *addressSectionInternal) getSubSection(index, endIndex int) *AddressSection {
	if index < 0 {
		index = 0
	}
	thisSegmentCount := section.GetSegmentCount()
	if endIndex < thisSegmentCount {
		endIndex = thisSegmentCount
	}
	segmentCount := endIndex - index
	if segmentCount <= 0 {
		if thisSegmentCount == 0 {
			return section.toAddressSection()
		}
		return zeroSection
	}
	if index == 0 && endIndex == thisSegmentCount {
		return section.toAddressSection()
	}
	segs := createSegmentArray(segmentCount)
	section.copySubSegmentsToSlice(index, endIndex, segs)
	newPrefLen := section.GetPrefixLength()
	if newPrefLen != nil && index != 0 {
		newPrefLen = getPrefixedSegmentPrefixLength(section.GetBitsPerSegment(), *newPrefLen, index)
	}
	newStartIndex := section.addressSegmentIndex + uint8(index)
	addrType := section.getAddrType()
	if !section.IsMultiple() {
		return createSection(segs, newPrefLen, addrType, newStartIndex)
	}
	return createInitializedSection(segs, newPrefLen, addrType, newStartIndex)
}

func (section *addressSectionInternal) copySegmentsToSlice(divs []*AddressDivision) (count int) {
	return section.visitSegments(func(index int, div *AddressDivision) bool { divs[index] = div; return false }, len(divs))
}

func (section *addressSectionInternal) visitSegments(target func(index int, div *AddressDivision) bool, targetLen int) (count int) {
	if section.hasNoDivisions() {
		return
	}
	count = section.GetDivisionCount()
	if count > targetLen {
		count = targetLen
	}
	for start := 0; start < count; start++ {
		if target(start, section.getDivision(start)) {
			break
		}
	}
	return
}

func (section *addressSectionInternal) copySubSegmentsToSlice(start, end int, divs []*AddressDivision) (count int) {
	return section.visitSubSegments(start, end, func(index int, div *AddressDivision) bool { divs[index] = div; return false }, len(divs))
}

func (section *addressSectionInternal) visitSubSegments(start, end int, target func(index int, div *AddressDivision) (stop bool), targetLen int) (count int) {
	if section.hasNoDivisions() {
		return
	}
	targetIndex := 0
	if start < 0 {
		targetIndex -= start
		start = 0
		if targetIndex >= targetLen {
			return
		}
	}
	// how many to copy?
	sourceLen := section.GetDivisionCount()
	if end > sourceLen {
		end = sourceLen
	}
	calcCount := end - start
	if calcCount <= 0 {
		return
	}
	// if not enough space, adjust count and end
	space := targetLen - targetIndex
	if calcCount > space {
		count = space
		end = start + space
	} else {
		count = calcCount
	}
	// now copy
	for start < end {
		if target(targetIndex, section.getDivision(start)) {
			break
		}
		targetIndex++
		start++
	}
	return
}

func (section *addressSectionInternal) getLowestOrHighestSection(lowest bool) (result *AddressSection) { //TODO move this too
	if !section.IsMultiple() {
		return section.toAddressSection()
	}
	cache := section.cache
	sectionCache := &cache.sectionCache
	cache.cacheLock.RLock()
	if lowest {
		result = sectionCache.lower
	} else {
		result = sectionCache.upper
	}
	cache.cacheLock.RUnlock()
	if result != nil {
		return
	}
	cache.cacheLock.Lock()
	if lowest {
		result = sectionCache.lower
		if result == nil {
			result = section.createLowestOrHighestSectionCacheLocked(lowest)
			sectionCache.lower = result
		}
	} else {
		result = sectionCache.upper
		if result == nil {
			result = section.createLowestOrHighestSectionCacheLocked(lowest)
			sectionCache.upper = result
		}
	}
	cache.cacheLock.Unlock()
	return
}

func (section *addressSectionInternal) createLowestOrHighestSectionCacheLocked(lowest bool) *AddressSection {
	segmentCount := section.GetSegmentCount()
	segs := createSegmentArray(segmentCount)
	if lowest {
		for i := 0; i < segmentCount; i++ {
			segs[i] = section.GetSegment(i).GetLower().ToAddressDivision()
		}
	} else {
		for i := 0; i < segmentCount; i++ {
			segs[i] = section.GetSegment(i).GetUpper().ToAddressDivision()
		}
	}
	return createSection(segs, section.prefixLength, section.getAddrType(), section.addressSegmentIndex)
}

func (section *addressSectionInternal) toPrefixBlock() *AddressSection {
	prefixLength := section.GetPrefixLength()
	if prefixLength == nil {
		return section.toAddressSection()
	}
	return section.toPrefixBlockLen(*prefixLength)
}

func (section *addressSectionInternal) toPrefixBlockLen(prefLen BitCount) *AddressSection {
	bitCount := section.GetBitCount()
	if prefLen < 0 {
		prefLen = 0
	} else {
		if prefLen > bitCount {
			prefLen = bitCount
		}
	}
	segCount := section.GetSegmentCount()
	if segCount == 0 {
		return section.toAddressSection()
	}
	segmentByteCount := section.GetBytesPerSegment()
	segmentBitCount := section.GetBitsPerSegment()
	existingPrefixLength := section.GetPrefixLength()
	prefixMatches := existingPrefixLength != nil && *existingPrefixLength == prefLen
	if prefixMatches {
		prefixedSegmentIndex := getHostSegmentIndex(prefLen, segmentByteCount, segmentBitCount)
		if prefixedSegmentIndex >= segCount {
			return section.toAddressSection()
		}
		segPrefLength := *getPrefixedSegmentPrefixLength(segmentBitCount, prefLen, prefixedSegmentIndex)
		seg := section.GetSegment(prefixedSegmentIndex)
		if seg.containsPrefixBlock(segPrefLength) {
			i := prefixedSegmentIndex + 1
			for ; i < segCount; i++ {
				seg = section.GetSegment(i)
				if !seg.IsFullRange() {
					break
				}
			}
			if i == segCount {
				return section.toAddressSection()
			}
		}
	}
	prefixedSegmentIndex := 0
	newSegs := createSegmentArray(segCount)
	if prefLen > 0 {
		prefixedSegmentIndex = getNetworkSegmentIndex(prefLen, segmentByteCount, segmentBitCount)
		section.copySubDivisions(0, prefixedSegmentIndex, newSegs)
		//copy(newSegs, section.divisions[:prefixedSegmentIndex])

	}
	for i := prefixedSegmentIndex; i < segCount; i++ {
		segPrefLength := getPrefixedSegmentPrefixLength(segmentBitCount, prefLen, i)
		oldSeg := section.getDivision(i)
		newSegs[i] = oldSeg.toPrefixedNetworkDivision(segPrefLength)
	}
	return createMultipleSection(newSegs, cacheBitCount(prefLen), section.getAddrType(), section.addressSegmentIndex, section.IsMultiple() || prefLen < bitCount)
}

func (section *addressSectionInternal) withoutPrefixLength() *AddressSection {
	if !section.IsPrefixed() {
		return section.toAddressSection()
	}
	return createSection(section.getDivisionsInternal(), nil, section.getAddrType(), section.addressSegmentIndex)
}

func (section *addressSectionInternal) Contains(other AddressSectionType) bool {
	otherSection := other.ToAddressSection()
	if section.toAddressSection() == otherSection {
		return true
	}
	//check if they are comparable first
	matches, count := section.matchesStructure(other)
	if !matches || count != other.GetDivisionCount() {
		return false
	} else {
		for i := count - 1; i >= 0; i-- {
			seg := section.GetSegment(i)
			if !seg.Contains(otherSection.GetSegment(i)) {
				return false
			}
		}
	}
	return true
}

//TODO the four string methods at address level are toCanonicalString, toNormalizedString, toHexString, toCompressedString
// we also want toCanonicalWildcardString and ToNormalizedWildcardString
// the code will need to check the addrtype in the section,
// and scale up to ipv6 or ipv4 or mac, or maybe do an if/elseif/else, not sure which is better
func (section *addressSectionInternal) ToCanonicalString() string {
	//TODO
	return ""
}

func (section *addressSectionInternal) ToCanonicalWildcardString() string {
	//TODO
	return ""
}

func (section *addressSectionInternal) ToNormalizedString() string {
	//TODO
	return ""
}

func (section *addressSectionInternal) ToNormalizedWildcardString() string {
	//TODO
	return ""
}

func (section *addressSectionInternal) GetSegmentStrings() []string {
	count := section.GetSegmentCount()
	res := make([]string, count)
	for i := 0; i < count; i++ {
		res[i] = section.GetSegment(i).String()
	}
	return res
}

// used by iterator() and nonZeroHostIterator() in section classes
func (section *addressSectionInternal) sectionIterator(
	creator ParsedAddressCreator, /* nil for zero sections */
	excludeFunc func([]*AddressDivision) bool) SectionIterator {
	if creator == nil { // zero section, all other sections have a creator associated
		return &singleSectionIterator{original: section.toAddressSection()}
	}
	isMult := section.IsMultiple()
	useOriginal := !isMult
	var original *AddressSection
	var iterator SegmentsIterator
	if useOriginal {
		if excludeFunc != nil {
			divs := section.getDivisionsInternal()
			if !excludeFunc(divs) {
				original = section.toAddressSection()
			} else {
				useOriginal = false
				iterator = allSegmentsIterator(
					section.GetSegmentCount(),
					nil,
					func(index int) SegmentIterator { return section.GetSegment(index).iterator() },
					excludeFunc)
			}
		} else {
			original = section.toAddressSection()
		}
	} else {
		iterator = allSegmentsIterator(
			section.GetSegmentCount(),
			nil,
			func(index int) SegmentIterator { return section.GetSegment(index).iterator() },
			excludeFunc)
	}
	return sectIterator(
		useOriginal,
		original,
		creator,
		iterator,
		section.prefixLength)
}

func (section *addressSectionInternal) prefixIterator(creator ParsedAddressCreator /* nil for zero sections */, isBlockIterator bool) SectionIterator {
	prefLen := section.prefixLength
	if prefLen == nil {
		return section.sectionIterator(creator, nil)
	}
	prefLength := *prefLen
	if prefLength > section.GetBitCount() {
		return section.sectionIterator(creator, nil)
	} else if creator == nil { // zero section, all other sections have a creator associated
		return &singleSectionIterator{original: section.toAddressSection()}
	}
	var useOriginal bool
	if isBlockIterator {
		useOriginal = section.IsSinglePrefixBlock()
	} else {
		useOriginal = section.GetPrefixCount().CmpAbs(bigOneConst()) == 0
	}
	bitsPerSeg := section.GetBitsPerSegment()
	bytesPerSeg := section.GetBytesPerSegment()
	networkSegIndex := getNetworkSegmentIndex(prefLength, bytesPerSeg, bitsPerSeg)
	hostSegIndex := getHostSegmentIndex(prefLength, bytesPerSeg, bitsPerSeg)
	segCount := section.GetSegmentCount()
	var iterator SegmentsIterator
	if !useOriginal {
		var hostSegIteratorProducer func(index int) SegmentIterator
		if isBlockIterator {
			hostSegIteratorProducer = func(index int) SegmentIterator {
				return section.GetSegment(index).prefixBlockIterator()
			}
		} else {
			hostSegIteratorProducer = func(index int) SegmentIterator {
				return section.GetSegment(index).prefixIterator()
			}
		}
		iterator = segmentsIterator(
			segCount,
			nil, //when no prefix we defer to other iterator, when there is one we use the whole original section in the encompassing iterator and not just the original segments
			func(index int) SegmentIterator { return section.GetSegment(index).iterator() },
			nil,
			networkSegIndex,
			hostSegIndex,
			hostSegIteratorProducer)
	}
	return sectIterator(
		useOriginal,
		section.toAddressSection(),
		creator,
		iterator,
		prefLen)
}

// TODO NEXT
// count code is done everywhere, see bottom of sectiterator.go for summary of remainig work,
// basically I got the basic iterators done everywhere except in seq ranges,
// and no other iterators done but the framework is ready for all of them
// TODO seq range iterators
//	prefixIterator built from the prefixBlockIterator
//	prefixBlockIterator and regular iterator use the same megafunc
// TODO all the address iterators corresponding to these section iterators

//xxx blcok iterators next xxx;

//TODO thinking ahead, for address iteratros, do we wrap section iterators, or do the same as java and copy the section iterators
// well we do use createAddressInternal, so what does that buy us?  it just uses createPrefixedSectionInternal
// section uses createPrefixedSectionInternal
// so it seems we gain nothing?  I think we may want to wrap.
// In reality, in java nad here, copying is not a lot of extra code.  It's the segments iterator that does all the work.
// AH BUT for when you want to use the original, then, there is a motivation!  That is when it is better.
// So let's do it the same as Java.

func (section *addressSectionInternal) isMultipleTo(segmentCount int) bool {
	for i := 0; i < segmentCount; i++ {
		if section.GetSegment(i).IsMultiple() {
			return true
		}
	}
	return false
}

func (section *addressSectionInternal) blockIterator(creator ParsedAddressCreator /* nil for zero sections */, segmentCount int) SectionIterator {
	if segmentCount < 0 {
		segmentCount = 0
	}
	allSegsCount := section.GetSegmentCount()
	if segmentCount >= allSegsCount {
		return section.sectionIterator(creator, nil)
	}
	useOriginal := !section.isMultipleTo(segmentCount)
	var iterator SegmentsIterator
	if !useOriginal {
		var hostSegIteratorProducer func(index int) SegmentIterator
		hostSegIteratorProducer = func(index int) SegmentIterator {
			return section.GetSegment(index).identityIterator()
		}
		segIteratorProducer := func(index int) SegmentIterator {
			return section.GetSegment(index).iterator()
		}
		iterator = segmentsIterator(
			allSegsCount,
			//creator,
			nil, //when no prefix we defer to other iterator, when there is one we use the whole original section in the encompassing iterator and not just the original segments
			segIteratorProducer,
			nil,
			segmentCount-1,
			segmentCount,
			hostSegIteratorProducer)
	}
	return sectIterator(
		useOriginal,
		section.toAddressSection(),
		creator,
		iterator,
		section.GetPrefixLength())
}

func (section *addressSectionInternal) sequentialBlockIterator(creator ParsedAddressCreator /* nil for zero sections */) SectionIterator {
	return section.blockIterator(creator, section.GetSequentialBlockIndex())
}

//
//
//
//
type AddressSection struct {
	addressSectionInternal
}

func (section *AddressSection) ContainsPrefixBlock(prefixLen BitCount) bool {
	prefixLen = checkSubnet(section, prefixLen)
	divCount := section.GetSegmentCount()
	bitsPerSegment := section.GetBitsPerSegment()
	i := getHostSegmentIndex(prefixLen, section.GetBytesPerSegment(), bitsPerSegment)
	if i < divCount {
		div := section.GetSegment(i)
		segmentPrefixLength := getPrefixedSegmentPrefixLength(bitsPerSegment, prefixLen, i)
		if !div.ContainsPrefixBlock(*segmentPrefixLength) {
			return false
		}
		for i++; i < divCount; i++ {
			div = section.GetSegment(i)
			if !div.IsFullRange() {
				return false
			}
		}
	}
	return true
}

func (section *AddressSection) GetCount() *big.Int {
	if sect := section.ToIPv4AddressSection(); sect != nil {
		return sect.GetCount()
	} else if sect := section.ToIPv6AddressSection(); sect != nil {
		return sect.GetCount()
	} else if sect := section.ToMACAddressSection(); sect != nil {
		return sect.GetCount()
	}
	return section.addressDivisionGroupingBase.GetCount()
}

func (section *AddressSection) GetPrefixCount() *big.Int {
	if sect := section.ToIPv4AddressSection(); sect != nil {
		return sect.GetPrefixCount()
	} else if sect := section.ToIPv6AddressSection(); sect != nil {
		return sect.GetPrefixCount()
	} else if sect := section.ToMACAddressSection(); sect != nil {
		return sect.GetPrefixCount()
	}
	return section.addressDivisionGroupingBase.GetPrefixCount()
}

func (section *AddressSection) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	if !section.IsMultiple() {
		return bigOne()
	} else if sect := section.ToIPv4AddressSection(); sect != nil {
		return sect.GetPrefixCountLen(prefixLen)
	} else if sect := section.ToIPv6AddressSection(); sect != nil {
		return sect.GetPrefixCountLen(prefixLen)
	} else if sect := section.ToMACAddressSection(); sect != nil {
		return sect.GetPrefixCountLen(prefixLen)
	}
	return section.addressDivisionGroupingBase.GetPrefixCountLen(prefixLen)
}

//func (section *AddressSection) IsMore(other *AddressSection) int {
//	return section.isMore(other.toAddressDivisionGrouping())
//}

// Gets the subsection from the series starting from the given index
// The first segment is at index 0.
func (section *AddressSection) GetTrailingSection(index int) *AddressSection {
	return section.getSubSection(index, section.GetSegmentCount())
}

//// Gets the subsection from the series starting from the given index and ending just before the give endIndex
//// The first segment is at index 0.
func (section *AddressSection) GetSubSection(index, endIndex int) *AddressSection {
	return section.getSubSection(index, endIndex)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *AddressSection) CopySubSegments(start, end int, segs []*AddressSegment) (count int) {
	return section.visitSubSegments(start, end, func(index int, div *AddressDivision) bool { segs[index] = div.ToAddressSegment(); return false }, len(segs))
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *AddressSection) CopySegments(segs []*AddressSegment) (count int) {
	return section.visitSegments(func(index int, div *AddressDivision) bool { segs[index] = div.ToAddressSegment(); return false }, len(segs))
}

// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this section.
func (section *AddressSection) GetSegments() (res []*AddressSegment) {
	res = make([]*AddressSegment, section.GetSegmentCount())
	section.CopySegments(res)
	return
}

func (section *AddressSection) GetLower() *AddressSection {
	return section.getLowestOrHighestSection(true)
}

func (section *AddressSection) GetUpper() *AddressSection {
	return section.getLowestOrHighestSection(false)
}

func (section *AddressSection) ToPrefixBlock() *AddressSection {
	return section.toPrefixBlock()
}

func (section *AddressSection) ToPrefixBlockLen(prefLen BitCount) *AddressSection {
	return section.toPrefixBlockLen(prefLen)
}

func (section *AddressSection) IsIPAddressSection() bool {
	return section != nil && section.matchesIPSection()
}

func (section *AddressSection) IsIPv4AddressSection() bool { //TODO maybe rename all these to IsIPv4(), same for IPv6() and maybe isMAC()
	return section != nil && section.matchesIPv4Section()
}

func (section *AddressSection) IsIPv6AddressSection() bool {
	return section != nil && section.matchesIPv6Section()
}

func (section *AddressSection) IsMACAddressSection() bool {
	return section != nil && section.matchesMACSection()
}

func (section *AddressSection) ToIPAddressSection() *IPAddressSection {
	if section.IsIPAddressSection() {
		return (*IPAddressSection)(unsafe.Pointer(section))
	}
	return nil
}

func (section *AddressSection) ToIPv6AddressSection() *IPv6AddressSection {
	if section.IsIPv6AddressSection() {
		return (*IPv6AddressSection)(unsafe.Pointer(section))
	}
	return nil
}

func (section *AddressSection) ToIPv4AddressSection() *IPv4AddressSection {
	if section.IsIPv4AddressSection() {
		return (*IPv4AddressSection)(unsafe.Pointer(section))
	}
	return nil
}

func (section *AddressSection) ToMACAddressSection() *MACAddressSection {
	if section.IsMACAddressSection() {
		return (*MACAddressSection)(unsafe.Pointer(section))
	}
	return nil
}

func (section *AddressSection) ToAddressSection() *AddressSection {
	return section
}

func (section *AddressSection) Iterator() SectionIterator {
	return section.sectionIterator(section.getAddrType().getCreator(), nil)
}

func (section *AddressSection) PrefixIterator() SectionIterator {
	return section.prefixIterator(section.getAddrType().getCreator(), false)
}

func (section *AddressSection) PrefixBlockIterator() SectionIterator {
	return section.prefixIterator(section.getAddrType().getCreator(), true)
}
