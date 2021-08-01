package ipaddr

import (
	"math/big"
	"sync/atomic"
	"unsafe"
)

var zeroSection = createSection(zeroDivs, nil, zeroType, 0)

func createSection(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType, startIndex int8) *AddressSection {
	sect := &AddressSection{
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
	assignStringCache(&sect.addressDivisionGroupingBase, addrType)
	return sect
}

func createSectionMultiple(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType, startIndex int8, isMultiple bool) *AddressSection {
	result := createSection(segments, prefixLength, addrType, startIndex)
	result.isMultiple = isMultiple
	return result
}

func createInitializedSection(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType, startIndex int8) *AddressSection {
	result := createSection(segments, prefixLength, addrType, startIndex)
	_ = result.initMultAndPrefLen() // assigns isMultiple and checks prefix length
	return result
}

func deriveAddressSectionPrefLen(from *AddressSection, segments []*AddressDivision, prefixLength PrefixLen) *AddressSection {
	return createInitializedSection(segments, prefixLength, from.getAddrType(), from.addressSegmentIndex)
}

func deriveAddressSection(from *AddressSection, segments []*AddressDivision) (res *AddressSection) {
	return deriveAddressSectionPrefLen(from, segments, from.prefixLength)
}

/*
// TODO MAC may need something like this when calculating prefix length on creation
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

func assignStringCache(section *addressDivisionGroupingBase, addrType addrType) {
	stringCache := &section.cache.stringCache
	if addrType.isIPv4() {
		stringCache.ipStringCache = &ipStringCache{}
		stringCache.ipv4StringCache = &ipv4StringCache{}
	} else if addrType.isIPv6() {
		stringCache.ipStringCache = &ipStringCache{}
		stringCache.ipv6StringCache = &ipv6StringCache{}
	} else if addrType.isMAC() {
		stringCache.macStringCache = &macStringCache{}
	}
}

//////////////////////////////////////////////////////////////////
//
//
//
type addressSectionInternal struct {
	addressDivisionGroupingInternal
}

// error returned for nil sements, or inconsistent prefixes
func (section *addressSectionInternal) initMultiple() {
	segCount := section.GetSegmentCount()
	for i := segCount - 1; i >= 0; i-- {
		segment := section.GetSegment(i)
		if segment.IsMultiple() {
			section.isMultiple = true
			return
		}
	}
	return
}

// error returned for nil sements, or inconsistent prefixes
func (section *addressSectionInternal) initMultAndPrefLen() AddressValueError {
	segCount := section.GetSegmentCount()
	if segCount != 0 {
		var previousSegmentPrefix PrefixLen
		isMultiple := false
		bitsPerSegment := section.GetBitsPerSegment()
		for i := 0; i < segCount; i++ {
			segment := section.GetSegment(i)
			if segment == nil {
				return &addressValueError{addressError: addressError{key: "ipaddress.error.null.segment"}}
			}

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
					pref := *segPrefix
					newPref := getNetworkPrefixLength(bitsPerSegment, pref, i)
					// if a section prefix was supplied, it will be assigned already and must align with the segments
					if section.prefixLength != nil {
						if *section.prefixLength != *newPref {
							return &inconsistentPrefixError{
								addressValueError{
									addressError: addressError{
										key: "ipaddress.error.inconsistent.prefixes",
									},
								},
							}
						}
					} else {
						section.prefixLength = newPref
					}
				}
			} else if segPrefix == nil || *segPrefix != 0 {
				return &inconsistentPrefixError{
					addressValueError{
						addressError: addressError{
							key: "ipaddress.error.inconsistent.prefixes",
						},
					},
				}
			}
			previousSegmentPrefix = segPrefix
		}
	}
	return nil
}

func (section *addressSectionInternal) EqualsSection(other *AddressSection) bool {
	matchesStructure, _ := section.matchesTypeAndCount(other)
	return matchesStructure && section.sameCountTypeEquals(other)
}

func (section *addressSectionInternal) sameCountTypeEquals(other *AddressSection) bool {
	count := section.GetSegmentCount()
	for i := count - 1; i >= 0; i-- {
		if !section.GetSegment(i).sameTypeEquals(other.GetSegment(i)) {
			return false
		}
	}
	return true
}

func (section *addressSectionInternal) sameCountTypeContains(other *AddressSection) bool {
	count := section.GetSegmentCount()
	for i := count - 1; i >= 0; i-- {
		if !section.GetSegment(i).sameTypeContains(other.GetSegment(i)) {
			return false
		}
	}
	return true
}

func (section *addressSectionInternal) GetBitsPerSegment() BitCount {
	addrType := section.getAddrType()
	if addrType.isIPv4() {
		return IPv4BitsPerSegment
	} else if addrType.isIPv6() {
		return IPv6BitsPerSegment
	} else if addrType.isMAC() {
		return MACBitsPerSegment
	}
	if section.GetDivisionCount() == 0 {
		return 0
	}
	return section.getDivision(0).GetBitCount()
}

func (section *addressSectionInternal) GetBytesPerSegment() int {
	addrType := section.getAddrType()
	if addrType.isIPv4() {
		return IPv4BytesPerSegment
	} else if addrType.isIPv6() {
		return IPv6BytesPerSegment
	} else if addrType.isMAC() {
		return MACBytesPerSegment
	}
	if section.GetDivisionCount() == 0 {
		return 0
	}
	return section.getDivision(0).GetByteCount()
}

func (section *addressSectionInternal) GetSegment(index int) *AddressSegment {
	return section.getDivision(index).ToAddressSegment()
}

// GetGenericSegment returns the segment as an AddressSegmentType,
// allowing all segment types to be represented by a single type
func (section *addressSectionInternal) GetGenericSegment(index int) AddressSegmentType {
	return section.GetSegment(index)
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
	addrType := section.getAddrType()
	if addrType.isIPv4() {
		return IPv4MaxValuePerSegment
	} else if addrType.isIPv6() {
		return IPv6MaxValuePerSegment
	} else if addrType.isMAC() {
		return MACMaxValuePerSegment
	}
	divLen := section.GetDivisionCount()
	if divLen == 0 {
		return 0
	}
	return section.GetSegment(0).GetMaxValue()
}

// TestBit computes (this & (1 << n)) != 0), using the lower value of this segment.
func (section *addressSectionInternal) TestBit(n BitCount) bool {
	return section.IsOneBit(section.GetBitCount() - (n + 1))
}

// IsOneBit returns true if the bit in the lower value of this section at the given index is 1, where index 0 is the most significant bit.
func (section *addressSectionInternal) IsOneBit(prefixBitIndex BitCount) bool {
	bitsPerSegment := section.GetBitsPerSegment()
	bytesPerSegment := section.GetBytesPerSegment()
	segment := section.GetSegment(getHostSegmentIndex(prefixBitIndex, bytesPerSegment, bitsPerSegment))
	segmentBitIndex := prefixBitIndex % bitsPerSegment
	return segment.IsOneBit(segmentBitIndex)
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
	newStartIndex := section.addressSegmentIndex + int8(index)
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

func (section *addressSectionInternal) getLowestHighestSections() (lower, upper *AddressSection) {
	if !section.IsMultiple() {
		lower = section.toAddressSection()
		upper = lower
		return
	}
	cache := section.cache
	cached := cache.sectionCache
	if cached == nil {
		cached = &groupingCache{}
		cached.lower, cached.upper = section.createLowestHighestSections()
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.sectionCache))
		atomic.StorePointer(dataLoc, unsafe.Pointer(cached))
	}
	lower = cached.lower
	upper = cached.upper
	return
}

func (section *addressSectionInternal) createLowestHighestSections() (lower, upper *AddressSection) {
	segmentCount := section.GetSegmentCount()
	lowSegs := createSegmentArray(segmentCount)
	var highSegs []*AddressDivision
	if section.IsMultiple() {
		highSegs = createSegmentArray(segmentCount)
	}
	for i := 0; i < segmentCount; i++ {
		seg := section.GetSegment(i)
		lowSegs[i] = seg.GetLower().ToAddressDivision()
		if highSegs != nil {
			highSegs[i] = seg.GetUpper().ToAddressDivision()
		}
	}
	//pref, addrType, ind := section.prefixLength, section.getAddrType(), section.addressSegmentIndex
	lower = deriveAddressSection(section.toAddressSection(), lowSegs)
	//lower = createSection(lowSegs, pref, addrType, ind)
	if highSegs == nil {
		upper = lower
	} else {
		upper = deriveAddressSection(section.toAddressSection(), highSegs)
		//upper = createSection(highSegs, pref, addrType, ind)
	}
	return
}

func (section *addressSectionInternal) reverseSegments(segProducer func(int) (*AddressSegment, IncompatibleAddressError)) (res *AddressSection, err IncompatibleAddressError) {
	count := section.GetSegmentCount()
	if count == 0 { // case count == 1 we cannot exit early, we need to apply segProducer to each segment
		if section.IsPrefixed() {
			return section.withoutPrefixLen(), nil
		}
		return section.toAddressSection(), nil
	}
	newSegs := createSegmentArray(count)
	halfCount := count >> 1
	i := 0
	isSame := !section.IsPrefixed() //when reversing, the prefix must go
	for j := count - 1; i < halfCount; i, j = i+1, j-1 {
		var segi, segj *AddressSegment
		if segi, err = segProducer(i); err != nil {
			return
		}
		if segj, err = segProducer(j); err != nil {
			return
		}
		origi := section.GetSegment(i)
		origj := section.GetSegment(j)
		newSegs[j] = segi.ToAddressDivision()
		newSegs[i] = segj.ToAddressDivision()
		if isSame &&
			!(segValsSame(segi.getSegmentValue(), origi.getSegmentValue(), segi.getUpperSegmentValue(), origi.getUpperSegmentValue()) &&
				segValsSame(segj.getSegmentValue(), origj.getSegmentValue(), segj.getUpperSegmentValue(), origj.getUpperSegmentValue())) {
			isSame = false
		}
	}
	if (count & 1) == 1 { //the count is odd, handle the middle one
		seg := section.getDivision(i)
		newSegs[i] = seg // gets segment i without prefix length
	}
	if isSame {
		res = section.toAddressSection() //We can do this because for ipv6 startIndex stays the same and for mac startIndex and extended stays the same
		return
	}
	res = deriveAddressSectionPrefLen(section.toAddressSection(), newSegs, nil)
	return
	//return creator.createSectionInternal(newSegs);
}

func (section *addressSectionInternal) reverseBits(perByte bool) (res *AddressSection, err IncompatibleAddressError) {
	if perByte {
		isSame := !section.IsPrefixed() //when reversing, the prefix must go
		count := section.GetSegmentCount()
		newSegs := createSegmentArray(count)
		for i := 0; i < count; i++ {
			seg := section.GetSegment(i)
			var reversedSeg *AddressSegment
			reversedSeg, err = seg.ReverseBits(perByte)
			if err != nil {
				return
			}
			newSegs[i] = reversedSeg.ToAddressDivision()
			if isSame && !segValsSame(seg.getSegmentValue(), reversedSeg.getSegmentValue(), seg.getUpperSegmentValue(), reversedSeg.getUpperSegmentValue()) {
				//if(isSame && !newSegs[i].equals(section.getSegment(i))) {
				isSame = false
			}
		}
		if isSame {
			res = section.toAddressSection() //We can do this because for ipv6 startIndex stays the same and for mac startIndex and extended stays the same
			return
		}
		res = deriveAddressSectionPrefLen(section.toAddressSection(), newSegs, nil)
		return
		//return creator.createSectionInternal(newSegs);
	}
	return section.reverseSegments(
		func(i int) (*AddressSegment, IncompatibleAddressError) {
			return section.GetSegment(i).ReverseBits(perByte)
		},
	)
}

func (section *addressSectionInternal) reverseBytes(perSegment bool) (res *AddressSection, err IncompatibleAddressError) {
	if perSegment {
		isSame := !section.IsPrefixed() //when reversing, the prefix must go
		count := section.GetSegmentCount()
		newSegs := createSegmentArray(count)
		for i := 0; i < count; i++ {
			seg := section.GetSegment(i)
			var reversedSeg *AddressSegment
			reversedSeg, err = seg.ReverseBytes()
			if err != nil {
				return
			}
			newSegs[i] = reversedSeg.ToAddressDivision()
			if isSame && !segValsSame(seg.getSegmentValue(), reversedSeg.getSegmentValue(), seg.getUpperSegmentValue(), reversedSeg.getUpperSegmentValue()) {
				//if(isSame && !newSegs[i].equals(section.getSegment(i))) {
				isSame = false
			}
			//if(isSame && !newSegs[i].equals(section.getSegment(i))) {
			//	isSame = false;
			//}
		}
		if isSame {
			res = section.toAddressSection() //We can do this because for ipv6 startIndex stays the same and for mac startIndex and extended stays the same
			return
		}
		res = deriveAddressSectionPrefLen(section.toAddressSection(), newSegs, nil)
		//return creator.createSectionInternal(newSegs);
		return
	}
	return section.reverseSegments(
		func(i int) (*AddressSegment, IncompatibleAddressError) { return section.GetSegment(i).ReverseBytes() },
	)
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
	return createSectionMultiple(newSegs, cacheBitCount(prefLen), section.getAddrType(), section.addressSegmentIndex, section.IsMultiple() || prefLen < bitCount)
}

func (section *addressSectionInternal) toBlock(segmentIndex int, lower, upper SegInt) *AddressSection {
	segCount := section.GetSegmentCount()
	i := segmentIndex
	if i < 0 {
		i = 0
	}
	maxSegVal := section.GetMaxSegmentValue()
	for ; i < segCount; i++ {
		seg := section.GetSegment(segmentIndex)
		var lowerVal, upperVal SegInt
		if i == segmentIndex {
			lowerVal, upperVal = lower, upper
		} else {
			upperVal = maxSegVal
		}
		if !segsSame(nil, seg.getDivisionPrefixLength(), lowerVal, seg.GetSegmentValue(), upperVal, seg.GetUpperSegmentValue()) {
			newSegs := createSegmentArray(segCount)
			section.copySubDivisions(0, i, newSegs)
			newSeg := createAddressDivision(seg.deriveNewMultiSeg(lowerVal, upperVal, nil))
			newSegs[i] = newSeg
			var allSeg *AddressDivision
			if j := i + 1; j < segCount {
				if i == segmentIndex {
					allSeg = createAddressDivision(seg.deriveNewMultiSeg(0, maxSegVal, nil))
				} else {
					allSeg = newSeg
				}
				newSegs[j] = allSeg
				for j++; j < segCount; j++ {
					newSegs[j] = allSeg
				}
			}
			return createSectionMultiple(newSegs, nil, section.getAddrType(), section.addressSegmentIndex,
				segmentIndex < segCount-1 || lower != upper)
		}
	}
	return section.toAddressSection()
}

func (section *addressSectionInternal) withoutPrefixLen() *AddressSection {
	if !section.IsPrefixed() {
		return section.toAddressSection()
	}
	return createSection(section.getDivisionsInternal(), nil, section.getAddrType(), section.addressSegmentIndex)
}

func (section *addressSectionInternal) setPrefixLen(prefixLen BitCount) *AddressSection {
	// no zeroing
	res, _ := section.setPrefixLength(prefixLen, false)
	return res
}

func (section *addressSectionInternal) setPrefixLenZeroed(prefixLen BitCount) (*AddressSection, IncompatibleAddressError) {
	return section.setPrefixLength(prefixLen, true)
}

func (section *addressSectionInternal) setPrefixLength(
	networkPrefixLength BitCount,
	withZeros bool,
) (res *AddressSection, err IncompatibleAddressError) {
	existingPrefixLength := section.GetPrefixLength()
	if existingPrefixLength != nil && networkPrefixLength == *existingPrefixLength {
		res = section.toAddressSection()
		return
	}
	checkSubnet(section, networkPrefixLength)
	var minPrefIndex, maxPrefIndex int
	var minPrefLen, maxPrefLen BitCount
	verifyMask := false
	bitsPerSegment := section.GetBitsPerSegment()
	bytesPerSegment := section.GetBytesPerSegment()
	prefIndex := getNetworkSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment)
	var startIndex int
	if existingPrefixLength != nil {
		existingPrefLen := *existingPrefixLength
		existingPrefIndex := getNetworkSegmentIndex(existingPrefLen, bytesPerSegment, bitsPerSegment)
		verifyMask = true
		if prefIndex > existingPrefIndex {
			maxPrefIndex = prefIndex
			minPrefIndex = existingPrefIndex
		} else {
			maxPrefIndex = existingPrefIndex
			minPrefIndex = prefIndex
		}
		if withZeros {
			if networkPrefixLength < existingPrefLen {
				minPrefLen = networkPrefixLength
				maxPrefLen = existingPrefLen
			} else {
				minPrefLen = existingPrefLen
				maxPrefLen = networkPrefixLength
			}
			startIndex = minPrefIndex
		} else {
			startIndex = minPrefIndex
			minPrefIndex = section.GetSegmentCount() // used for zeroing, so setting it to the end causes no zeroing
		}
	} else {
		minPrefIndex = section.GetSegmentCount()
		startIndex = prefIndex
	}
	maxVal := section.GetMaxSegmentValue()
	return section.getSubnetSegments(
		startIndex,
		cacheBitCount(networkPrefixLength),
		verifyMask,
		func(i int) *AddressDivision {
			return section.getDivision(i)
		},
		func(i int) SegInt {
			if i >= minPrefIndex {
				if i <= maxPrefIndex {
					minSegPrefLen := *getPrefixedSegmentPrefixLength(bitsPerSegment, minPrefLen, i)
					minMask := maxVal << uint(bitsPerSegment-minSegPrefLen)
					maxSegPrefLen := getPrefixedSegmentPrefixLength(bitsPerSegment, maxPrefLen, i)
					if maxSegPrefLen != nil {
						maxMask := maxVal << uint(bitsPerSegment-minSegPrefLen)
						return minMask | maxMask
					}
					return minMask
				}
			}
			return maxVal
		},
	)
}

func (section *addressSectionInternal) assignPrefixForSingleBlock() *AddressSection {
	newPrefix := section.GetPrefixLengthForSingleBlock()
	if newPrefix == nil {
		return nil
	}
	return section.setPrefixLen(*newPrefix)
}

// Constructs an equivalent address section with the smallest CIDR prefix possible (largest network),
// such that the range of values are a set of subnet blocks for that prefix.
func (section *addressSectionInternal) assignMinPrefixForBlock() *AddressSection {
	return section.setPrefixLen(section.GetMinPrefixLengthForBlock())
}

func (section *addressSectionInternal) PrefixEquals(other AddressSectionType) (res bool) {
	o := other.ToAddressSection()
	if section.toAddressSection() == o {
		return true
	} else if section.getAddrType() != o.getAddrType() {
		return
	}
	return section.addressSegmentIndex >= o.addressSegmentIndex && section.prefixContains(o, int(section.addressSegmentIndex-o.addressSegmentIndex), false)
}

func (section *addressSectionInternal) PrefixContains(other AddressSectionType) (res bool) {
	o := other.ToAddressSection()
	if section.toAddressSection() == o {
		return true
	} else if section.getAddrType() != o.getAddrType() {
		return
	}
	return section.addressSegmentIndex >= o.addressSegmentIndex && section.prefixContains(o, int(section.addressSegmentIndex-o.addressSegmentIndex), true)
}

func (section *addressSectionInternal) prefixContains(other *AddressSection, otherIndex int, contains bool) (res bool) {
	if otherIndex < 0 {
		return
	}
	prefixLength := section.GetPrefixLength()
	var prefixedSection int
	if prefixLength == nil {
		prefixedSection = section.GetSegmentCount()
		oIndex := prefixedSection + otherIndex
		if oIndex > other.GetSegmentCount() {
			return
		}
	} else {
		prefLen := *prefixLength
		prefixedSection = getNetworkSegmentIndex(prefLen, section.GetBytesPerSegment(), section.GetBitsPerSegment())
		if prefixedSection >= 0 {
			oIndex := prefixedSection + otherIndex
			if oIndex >= other.GetSegmentCount() {
				return
			}
			one := section.GetSegment(prefixedSection)
			two := other.GetSegment(oIndex)
			segPrefixLength := getPrefixedSegmentPrefixLength(one.getBitCount(), prefLen, prefixedSection)
			if contains {
				if !one.PrefixContains(two, *segPrefixLength) {
					return
				}
			} else {
				if !one.PrefixEquals(two, *segPrefixLength) {
					return
				}
			}
		}
	}

	for prefixedSection--; prefixedSection >= 0; prefixedSection-- {
		one := section.GetSegment(prefixedSection)
		two := other.GetSegment(prefixedSection + otherIndex)
		if contains {
			if !one.Contains(two) {
				return
			}
		} else {
			if !one.equalsSegment(two) {
				return
			}
		}
	}
	return true
}

func (section *addressSectionInternal) Contains(other AddressSectionType) bool {
	otherSection := other.ToAddressSection()
	if section.toAddressSection() == otherSection {
		return true
	}
	//check if they are comparable first
	matches, count := section.matchesTypeAndCount(other)
	if !matches {
		return false
	} else {
		for i := count - 1; i >= 0; i-- {
			if !section.GetSegment(i).sameTypeContains(otherSection.GetSegment(i)) {
				return false
			}
		}
	}
	return true
}

func (section *addressSectionInternal) ContainsPrefixBlock(prefixLen BitCount) bool {
	prefixLen = checkSubnet(section.toAddressSection(), prefixLen)
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

func (section *addressSectionInternal) getStringCache() *stringCache {
	if section.hasNoDivisions() {
		return &zeroStringCache
	}
	return &section.cache.stringCache
}

func (section *addressSectionInternal) getLower() *AddressSection {
	lower, _ := section.getLowestHighestSections()
	return lower
}

func (section *addressSectionInternal) getUpper() *AddressSection {
	_, upper := section.getLowestHighestSections()
	return upper
}

func (section *addressSectionInternal) incrementBoundary(increment int64) *AddressSection {
	if increment <= 0 {
		if increment == 0 {
			return section.toAddressSection()
		}
		return section.getLower().increment(increment)
	}
	return section.getUpper().increment(increment)
}

func (section *addressSectionInternal) increment(increment int64) *AddressSection {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.Increment(increment).ToAddressSection()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.Increment(increment).ToAddressSection()
	} else if sect := section.toMACAddressSection(); sect != nil {
		return sect.Increment(increment).ToAddressSection()
	}
	return nil
}

var (
	hexParams            = new(StringOptionsBuilder).SetRadix(16).SetHasSeparator(false).SetExpandedSegments(true).ToOptions()
	hexPrefixedParams    = new(StringOptionsBuilder).SetRadix(16).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(HexPrefix).ToOptions()
	octalParams          = new(StringOptionsBuilder).SetRadix(8).SetHasSeparator(false).SetExpandedSegments(true).ToOptions()
	octalPrefixedParams  = new(StringOptionsBuilder).SetRadix(8).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(OctalPrefix).ToOptions()
	binaryParams         = new(StringOptionsBuilder).SetRadix(2).SetHasSeparator(false).SetExpandedSegments(true).ToOptions()
	binaryPrefixedParams = new(StringOptionsBuilder).SetRadix(2).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(BinaryPrefix).ToOptions()
)

func (section *addressSectionInternal) ToCanonicalString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToCanonicalString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToCanonicalString()
	} else if sect := section.toMACAddressSection(); sect != nil {
		return sect.ToCanonicalString()
	}
	// zero section
	return "0"
}

func (section *addressSectionInternal) ToNormalizedString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToNormalizedString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToNormalizedString()
	} else if sect := section.toMACAddressSection(); sect != nil {
		return sect.ToNormalizedString()
	}
	return "0"
}

func (section *addressSectionInternal) ToCompressedString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToCompressedString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToCompressedString()
	} else if sect := section.toMACAddressSection(); sect != nil {
		return sect.ToCompressedString()
	}
	return "0"
}

func (section *addressSectionInternal) ToHexString(with0xPrefix bool) (string, IncompatibleAddressError) {
	var cacheField **string
	if with0xPrefix {
		cacheField = &section.getStringCache().hexStringPrefixed
	} else {
		cacheField = &section.getStringCache().hexString
	}
	return cacheStrErr(cacheField,
		func() (string, IncompatibleAddressError) {
			return section.toHexStringZoned(with0xPrefix, NoZone)
		})
}

func (section *addressSectionInternal) toHexStringZoned(with0xPrefix bool, zone Zone) (string, IncompatibleAddressError) {
	if with0xPrefix {
		return section.toLongStringZoned(zone, hexPrefixedParams)
	}
	return section.toLongStringZoned(zone, hexParams)
}

func (section *addressSectionInternal) toLongStringZoned(zone Zone, params StringOptions) (string, IncompatibleAddressError) {
	isDual, err := section.isDualString()
	if err != nil {
		return "", err
	}
	if isDual {
		sect := section.toAddressSection()
		return toNormalizedStringRange(toParams(params), sect.GetLower(), sect.GetUpper(), zone), nil
	}
	return section.toNormalizedOptsString(params), nil
}

func (section *addressSectionInternal) toNormalizedOptsString(stringOptions StringOptions) string {
	return toNormalizedString(stringOptions, section)
}

func (section *addressSectionInternal) isDualString() (bool, IncompatibleAddressError) {
	count := section.GetSegmentCount()
	for i := 0; i < count; i++ {
		division := section.GetSegment(i)
		if division.isMultiple() {
			//at this point we know we will return true, but we determine now if we must throw IncompatibleAddressError
			isLastFull := true
			for j := count - 1; j >= 0; j-- {
				division = section.GetSegment(j)
				if division.isMultiple() {
					if !isLastFull {
						return false, &incompatibleAddressError{addressError{key: "ipaddress.error.segmentMismatch"}}
					}
					isLastFull = division.IsFullRange()
				} else {
					isLastFull = false
				}
			}
			return true, nil
		}
	}
	return false, nil
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
func (section *addressSectionInternal) sectionIterator(excludeFunc func([]*AddressDivision) bool) SectionIterator {
	useOriginal := !section.IsMultiple()
	var original = section.toAddressSection()
	var iterator SegmentsIterator
	if useOriginal {
		if excludeFunc != nil && excludeFunc(section.getDivisionsInternal()) {
			original = nil // the single-valued iterator starts out empty
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
		false,
		iterator)
}

func (section *addressSectionInternal) prefixIterator(isBlockIterator bool) SectionIterator {
	prefLen := section.prefixLength
	if prefLen == nil {
		return section.sectionIterator(nil)
	}
	prefLength := *prefLen
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
	if isBlockIterator {
		return sectIterator(
			useOriginal,
			section.toAddressSection(),
			prefLength < section.GetBitCount(),
			iterator)
	}
	return prefixSectIterator(
		useOriginal,
		section.toAddressSection(),
		iterator)
}

func (section *addressSectionInternal) blockIterator(segmentCount int) SectionIterator {
	if segmentCount < 0 {
		segmentCount = 0
	}
	allSegsCount := section.GetSegmentCount()
	if segmentCount >= allSegsCount {
		return section.sectionIterator(nil)
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
		section.isMultipleFrom(segmentCount),
		iterator)
}

func (section *addressSectionInternal) sequentialBlockIterator() SectionIterator {
	return section.blockIterator(section.GetSequentialBlockIndex())
}

func (section *addressSectionInternal) GetSequentialBlockCount() *big.Int {
	sequentialSegCount := section.GetSequentialBlockIndex()
	return section.GetPrefixCountLen(BitCount(sequentialSegCount) * section.GetBitsPerSegment())
}

func (section *addressSectionInternal) isMultipleTo(segmentCount int) bool {
	for i := 0; i < segmentCount; i++ {
		if section.GetSegment(i).IsMultiple() {
			return true
		}
	}
	return false
}

func (section *addressSectionInternal) isMultipleFrom(segmentCount int) bool {
	segTotal := section.GetSegmentCount()
	for i := segmentCount; i < segTotal; i++ {
		if section.GetSegment(i).IsMultiple() {
			return true
		}
	}
	return false
}

func (section *addressSectionInternal) getSubnetSegments( // called by methods to adjust/remove/set prefix length, masking methods, zero host and zero network methods
	startIndex int,
	networkPrefixLength PrefixLen,
	verifyMask bool,
	segProducer func(int) *AddressDivision,
	segmentMaskProducer func(int) SegInt,
) (res *AddressSection, err IncompatibleAddressError) {
	networkPrefixLength = checkPrefLen(networkPrefixLength, section.GetBitCount())
	bitsPerSegment := section.GetBitsPerSegment()
	count := section.GetSegmentCount()
	for i := startIndex; i < count; i++ {
		segmentPrefixLength := getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i)
		seg := segProducer(i)
		//note that the mask can represent a range (for example a CIDR mask),
		//but we use the lowest value (maskSegment.value) in the range when masking (ie we discard the range)
		maskValue := segmentMaskProducer(i)
		origValue, origUpperValue := seg.getSegmentValue(), seg.getUpperSegmentValue()
		value, upperValue := origValue, origUpperValue
		if verifyMask {
			mask64 := uint64(maskValue)
			val64 := uint64(value)
			upperVal64 := uint64(upperValue)
			masker := maskRange(val64, upperVal64, mask64, seg.GetMaxValue())
			if !masker.IsSequential() {
				err = &incompatibleAddressError{addressError{key: "ipaddress.error.maskMismatch"}}
				return
			}
			value = SegInt(masker.GetMaskedLower(val64, mask64))
			upperValue = SegInt(masker.GetMaskedUpper(upperVal64, mask64))
		} else {
			value &= maskValue
			upperValue &= maskValue
		}
		if !segsSame(segmentPrefixLength, seg.getDivisionPrefixLength(), value, origValue, upperValue, origUpperValue) {
			newSegments := createSegmentArray(count)
			section.copySubSegmentsToSlice(0, i, newSegments)
			newSegments[i] = createAddressDivision(seg.deriveNewMultiSeg(value, upperValue, segmentPrefixLength))
			for i++; i < count; i++ {
				segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i)
				seg = segProducer(i)
				maskValue = segmentMaskProducer(i)
				origValue, origUpperValue = seg.getSegmentValue(), seg.getUpperSegmentValue()
				value, upperValue = origValue, origUpperValue
				if verifyMask {
					mask64 := uint64(maskValue)
					val64 := uint64(value)
					upperVal64 := uint64(upperValue)
					masker := maskRange(val64, upperVal64, mask64, seg.GetMaxValue())
					if !masker.IsSequential() {
						err = &incompatibleAddressError{addressError{key: "ipaddress.error.maskMismatch"}}
						return
					}
					value = SegInt(masker.GetMaskedLower(val64, mask64))
					upperValue = SegInt(masker.GetMaskedUpper(upperVal64, mask64))
				} else {
					value &= maskValue
					upperValue &= maskValue
				}
				if !segsSame(segmentPrefixLength, seg.getDivisionPrefixLength(), value, origValue, upperValue, origUpperValue) {
					newSegments[i] = createAddressDivision(seg.deriveNewMultiSeg(value, upperValue, segmentPrefixLength))
				} else {
					newSegments[i] = seg
				}
			}
			res = deriveAddressSectionPrefLen(section.toAddressSection(), newSegments, networkPrefixLength)
			return
		}
	}
	res = section.toAddressSection()
	return
}

func (section *addressSectionInternal) toAddressSection() *AddressSection {
	return (*AddressSection)(unsafe.Pointer(section))
}

func (section *addressSectionInternal) toIPAddressSection() *IPAddressSection {
	return section.toAddressSection().ToIPAddressSection()
}

func (section *addressSectionInternal) toIPv4AddressSection() *IPv4AddressSection {
	return section.toAddressSection().ToIPv4AddressSection()
}

func (section *addressSectionInternal) toIPv6AddressSection() *IPv6AddressSection {
	return section.toAddressSection().ToIPv6AddressSection()
}

func (section *addressSectionInternal) toMACAddressSection() *MACAddressSection {
	return section.toAddressSection().ToMACAddressSection()
}

func (section *addressSectionInternal) ToAddressDivisionGrouping() *AddressDivisionGrouping {
	return (*AddressDivisionGrouping)(section)
}

//
//
//
//
type AddressSection struct {
	addressSectionInternal
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

//func (section *AddressSection) CompareSize(other *AddressSection) int {
//	return section.CompareSize(other.toAddressDivisionGrouping())
//}

// Gets the subsection from the series starting from the given index
// The first segment is at index 0.
func (section *AddressSection) GetTrailingSection(index int) *AddressSection {
	return section.getSubSection(index, section.GetSegmentCount())
}

// Gets the subsection from the series starting from the given index and ending just before the give endIndex
// The first segment is at index 0.
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
	return section.getLower()
}

func (section *AddressSection) GetUpper() *AddressSection {
	return section.getUpper()
}

func (section *AddressSection) ToPrefixBlock() *AddressSection {
	return section.toPrefixBlock()
}

func (section *AddressSection) ToPrefixBlockLen(prefLen BitCount) *AddressSection {
	return section.toPrefixBlockLen(prefLen)
}

func (section *AddressSection) WithoutPrefixLen() *AddressSection {
	return section.withoutPrefixLen()
}

func (section *AddressSection) SetPrefixLen(prefixLen BitCount) *AddressSection {
	return section.setPrefixLen(prefixLen)
}

func (section *AddressSection) SetPrefixLenZeroed(prefixLen BitCount) (*AddressSection, IncompatibleAddressError) {
	return section.setPrefixLenZeroed(prefixLen)
}

func (section *AddressSection) AssignPrefixForSingleBlock() *AddressSection {
	return section.assignPrefixForSingleBlock()
}

func (section *AddressSection) AssignMinPrefixForBlock() *AddressSection {
	return section.assignMinPrefixForBlock()
}

func (section *AddressSection) ToBlock(segmentIndex int, lower, upper SegInt) *AddressSection {
	return section.toBlock(segmentIndex, lower, upper)
}

func (section *AddressSection) IsIPAddressSection() bool {
	return section != nil && section.matchesIPSectionType()
}

func (section *AddressSection) IsIPv4AddressSection() bool {
	return section != nil && section.matchesIPv4SectionType()
}

func (section *AddressSection) IsIPv6AddressSection() bool {
	return section != nil && section.matchesIPv6SectionType()
}

func (section *AddressSection) IsMACAddressSection() bool {
	return section != nil && section.matchesMACSectionType()
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
	return section.sectionIterator(nil)
}

func (section *AddressSection) PrefixIterator() SectionIterator {
	return section.prefixIterator(false)
}

func (section *AddressSection) PrefixBlockIterator() SectionIterator {
	return section.prefixIterator(true)
}

func (section *AddressSection) IncrementBoundary(increment int64) *AddressSection {
	return section.incrementBoundary(increment)
}

func (section *AddressSection) Increment(increment int64) *AddressSection {
	return section.increment(increment)
}

func (section *AddressSection) ReverseBits(perByte bool) (*AddressSection, IncompatibleAddressError) {
	return section.reverseBits(perByte)
}

func (section *AddressSection) ReverseBytes() (*AddressSection, IncompatibleAddressError) {
	return section.reverseBytes(false)
}

//func (section *AddressSection) ReverseBytesPerSegment() (*AddressSection, IncompatibleAddressError) {
//	return section.reverseBytes(true)
//}

func (section *AddressSection) ReverseSegments() *AddressSection {
	if section.GetSegmentCount() <= 1 {
		if section.IsPrefixed() {
			return section.WithoutPrefixLen()
		}
		return section
	}
	res, _ := section.reverseSegments(
		func(i int) (*AddressSegment, IncompatibleAddressError) {
			return section.GetSegment(i).withoutPrefixLen(), nil
		},
	)
	return res
}

func seriesValsSame(one, two AddressSegmentSeries) bool {
	if one == two {
		return true
	}
	count := one.GetDivisionCount()
	if count != two.GetDivisionCount() {
		panic(two)
	}
	for i := count - 1; i >= 0; i-- { // reverse order since less significant segments more likely to differ
		oneSeg := one.GetGenericSegment(i)
		twoSeg := two.GetGenericSegment(i)
		if !segValsSame(oneSeg.GetSegmentValue(), twoSeg.GetSegmentValue(),
			oneSeg.GetUpperSegmentValue(), twoSeg.GetUpperSegmentValue()) {
			return false
		}
	}
	return true
}
