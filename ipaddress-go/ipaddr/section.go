package ipaddr

import (
	"fmt"
	"math/big"
	"sync/atomic"
	"unsafe"
)

var zeroSection = createSection(zeroDivs, nil, zeroType)

func createSection(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType) *AddressSection {
	sect := &AddressSection{
		addressSectionInternal{
			addressDivisionGroupingInternal{
				addressDivisionGroupingBase: addressDivisionGroupingBase{
					divisions:    standardDivArray{segments},
					prefixLength: prefixLength,
					addrType:     addrType,
					cache:        &valueCache{},
				},
			},
		},
	}
	assignStringCache(&sect.addressDivisionGroupingBase, addrType)
	return sect
}

func createSectionMultiple(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType, isMultiple bool) *AddressSection {
	result := createSection(segments, prefixLength, addrType)
	result.isMult = isMultiple
	return result
}

func createInitializedSection(segments []*AddressDivision, prefixLength PrefixLen, addrType addrType) *AddressSection {
	result := createSection(segments, prefixLength, addrType)
	_ = result.initMultAndPrefLen() // assigns isMult and checks prefix length
	return result
}

func deriveAddressSectionPrefLen(from *AddressSection, segments []*AddressDivision, prefixLength PrefixLen) *AddressSection {
	return createInitializedSection(segments, prefixLength, from.getAddrType())
}

func deriveAddressSection(from *AddressSection, segments []*AddressDivision) (res *AddressSection) {
	return deriveAddressSectionPrefLen(from, segments, from.prefixLength)
}

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

// error returned for nil sements
func (section *addressSectionInternal) initMult() AddressValueError {
	segCount := section.GetSegmentCount()
	if segCount != 0 {
		isMultiple := false
		for i := 0; i < segCount; i++ {
			segment := section.GetSegment(i)
			if segment == nil {
				return &addressValueError{addressError: addressError{key: "ipaddress.error.null.segment"}}
			}
			if !isMultiple && segment.isMultiple() {
				isMultiple = true
				section.isMult = true
			}
		}
	}
	return nil
}

func (section *addressSectionInternal) initImplicitPrefLen(bitsPerSegment BitCount) {
	segCount := section.GetSegmentCount()
	if segCount != 0 {
		isBlock := true
		for i := segCount - 1; i >= 0; i-- {
			segment := section.GetSegment(i)
			if isBlock {
				minPref := segment.GetMinPrefixLenForBlock()
				if minPref > 0 {
					if minPref != bitsPerSegment || i != segCount-1 {
						section.prefixLength = getNetworkPrefixLen(bitsPerSegment, minPref, i)
					}
					isBlock = false
					break
				}
			}
		}
	}
}

// error returned for nil sements, or inconsistent prefixes
func (section *addressSectionInternal) initMultAndImplicitPrefLen(bitsPerSegment BitCount, checkAllSegs bool) AddressValueError {
	segCount := section.GetSegmentCount()
	if segCount != 0 {
		isMultiple := false
		isBlock := true
		for i := segCount - 1; i >= 0; i-- {
			segment := section.GetSegment(i)
			if segment == nil {
				return &addressValueError{addressError: addressError{key: "ipaddress.error.null.segment"}}
			}
			if isBlock {
				minPref := segment.GetMinPrefixLenForBlock()
				if minPref > 0 {
					if minPref != bitsPerSegment || i != segCount-1 {
						section.prefixLength = getNetworkPrefixLen(bitsPerSegment, minPref, i)
					}
					isBlock = false
				}
			}
			if !isMultiple && segment.isMultiple() {
				isMultiple = true
				section.isMult = true
			}
			if isMultiple && !isBlock && !checkAllSegs {
				break // isMult is known, isBlock is completed, and we don't need to verify the segs for nil
			}
		}
		if isBlock {
			section.prefixLength = cacheBitCount(0)
		}
	}
	return nil
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

			if !isMultiple && segment.isMultiple() {
				isMultiple = true
				section.isMult = true
			}

			//Calculate the segment-level prefix
			//
			//Across an address prefixes are:
			//IPv6: (null):...:(null):(1 to 16):(0):...:(0)
			//or IPv4: ...(null).(1 to 8).(0)...
			//For MACSize, all segs have nil prefix since prefix is not segment-level
			//For MACSize, prefixes must be derived in other ways, not from individual segment prefix values,
			// either using
			segPrefix := segment.getDivisionPrefixLength()
			if previousSegmentPrefix == nil {
				if segPrefix != nil {
					pref := *segPrefix
					newPref := getNetworkPrefixLen(bitsPerSegment, pref, i)
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

func (section *addressSectionInternal) matchesTypeAndCount(other *AddressSection) (matches bool, count int) {
	count = section.GetDivisionCount()
	if count != other.GetDivisionCount() {
		return
	} else if section.getAddrType() != other.getAddrType() {
		return
	}
	matches = true
	return
}

//func (section *addressSectionInternal) EqualsSection(other *AddressSection) bool {
//	matchesStructure, _ := section.matchesTypeAndCount(other)
//	return matchesStructure && section.sameCountTypeEquals(other)
//}
func (section *addressSectionInternal) equal(otherT AddressSectionType) bool {
	if otherT == nil {
		return false
	}
	other := otherT.ToAddressSection()
	if other == nil {
		return false
	}
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
	if endIndex > thisSegmentCount {
		endIndex = thisSegmentCount
	}
	segmentCount := endIndex - index
	if segmentCount <= 0 {
		if thisSegmentCount == 0 {
			return section.toAddressSection()
		} //else if section.GetPrefixLen() == nil {
		//xxxx do you want an incosistency where mac zero length can have prefix len zero while ip sections cannot? xxxx
		//xxxx hmmmm, not obvious
		//xxxx in ip, probably do not want to change the fact that segment prefixes must be in sync
		//xxxx in a way, it makes sense you would drop the prefix once bit len hits zero
		//xxxx
		return zeroSection
		//}
		//return zeroSectionPrefLenZero
	}
	if index == 0 && endIndex == thisSegmentCount {
		return section.toAddressSection()
	}
	segs := section.getSubDivisions(index, endIndex)
	newPrefLen := section.GetPrefixLen()
	if newPrefLen != nil {
		newPrefLen = getAdjustedPrefixLength(section.GetBitsPerSegment(), *newPrefLen, index, endIndex)
	}
	addrType := section.getAddrType()
	if !section.isMultiple() {
		return createSection(segs, newPrefLen, addrType)
	}
	return createInitializedSection(segs, newPrefLen, addrType)
}

func (section *addressSectionInternal) copySegmentsToSlice(divs []*AddressDivision) (count int) {
	return section.copyDivisions(divs)
	//return section.visitDivisions(func(index int, div *AddressDivision) bool { divs[index] = div; return false }, len(divs))
}

func (section *addressSectionInternal) copySubSegmentsToSlice(start, end int, divs []*AddressDivision) (count int) {
	return section.visitSubDivisions(start, end, func(index int, div *AddressDivision) bool { divs[index] = div; return false }, len(divs))
}

func (section *addressSectionInternal) getLowestHighestSections() (lower, upper *AddressSection) {
	if !section.isMultiple() {
		lower = section.toAddressSection()
		upper = lower
		return
	}
	cache := section.cache
	if cache == nil {
		return section.createLowestHighestSections()
	}
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
	if section.isMultiple() {
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
		var newj, newi *AddressSegment
		if newj, err = segProducer(i); err != nil {
			return
		}
		if newi, err = segProducer(j); err != nil {
			return
		}
		origi := section.GetSegment(i)
		origj := section.GetSegment(j)
		newSegs[j] = newj.ToAddressDivision()
		newSegs[i] = newi.ToAddressDivision()
		if isSame &&
			!(segValsSame(newi.getSegmentValue(), origi.getSegmentValue(), newi.getUpperSegmentValue(), origi.getUpperSegmentValue()) &&
				segValsSame(newj.getSegmentValue(), origj.getSegmentValue(), newj.getUpperSegmentValue(), origj.getUpperSegmentValue())) {
			//!(segValsSame(newj.getSegmentValue(), newi.getSegmentValue(), newj.getUpperSegmentValue(), newi.getUpperSegmentValue())) {
			isSame = false
		}
	}
	if (count & 1) == 1 { //the count is odd, handle the middle one
		seg := section.getDivision(i)
		newSegs[i] = seg // gets segment i without prefix length
	}
	if isSame {
		res = section.toAddressSection()
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

func (section *addressSectionInternal) replace(
	index,
	endIndex int,
	replacement *AddressSection,
	replacementStartIndex,
	replacementEndIndex int,
	prefixLen PrefixLen) *AddressSection {
	otherSegmentCount := replacementEndIndex - replacementStartIndex
	segmentCount := section.GetSegmentCount()
	totalSegmentCount := segmentCount + otherSegmentCount - (endIndex - index)
	segs := createSegmentArray(totalSegmentCount)
	sect := section.toAddressSection()
	sect.copySubSegmentsToSlice(0, index, segs)
	if index < totalSegmentCount {
		replacement.copySubSegmentsToSlice(replacementStartIndex, replacementEndIndex, segs[index:])
		if index+otherSegmentCount < totalSegmentCount {
			sect.copySubSegmentsToSlice(endIndex, segmentCount, segs[index+otherSegmentCount:])
		}
	}
	addrType := sect.getAddrType()
	if addrType.isNil() { // zero-length section
		addrType = replacement.getAddrType()
	}
	return createInitializedSection(segs, prefixLen, addrType)
	//return deriveAddressSectionPrefLen(sect, segs, prefixLen) xxx
}

// Replaces segments starting from startIndex and ending before endIndex with the segments starting at replacementStartIndex and
//ending before replacementEndIndex from the replacement section
func (section *addressSectionInternal) replaceLen(startIndex, endIndex int, replacement *AddressSection, replacementStartIndex, replacementEndIndex int, segmentToBitsShift uint) *AddressSection {

	segmentCount := section.GetSegmentCount()
	startIndex, endIndex, replacementStartIndex, replacementEndIndex =
		adjustIndices(startIndex, endIndex, segmentCount, replacementStartIndex, replacementEndIndex, replacement.GetSegmentCount())

	replacedCount := endIndex - startIndex
	replacementCount := replacementEndIndex - replacementStartIndex

	//		if(replacementCount == 0 && replacedCount == 0) {
	//			return this;
	//		} else if(addressSegmentIndex == replacement.addressSegmentIndex && extended == replacement.extended && segmentCount == replacedCount) {
	//			return replacement;
	//		}

	// unlike ipvx, sections of zero length with 0 prefix are still considered to be applying their prefix during replacement,
	// because you can have zero length prefixes when there are no bits in the section
	prefixLength := section.GetPrefixLen()
	if replacementCount == 0 && replacedCount == 0 {
		if prefixLength != nil {
			prefLen := *prefixLength
			if prefLen <= BitCount(startIndex<<segmentToBitsShift) {
				return section.toAddressSection()
			} else {
				replacementPrefisLength := replacement.GetPrefixLen()
				if replacementPrefisLength == nil {
					return section.toAddressSection()
				} else if *replacementPrefisLength > BitCount(replacementStartIndex<<segmentToBitsShift) {
					return section.toAddressSection()
				}
			}
		} else {
			replacementPrefisLength := replacement.GetPrefixLen()
			if replacementPrefisLength == nil {
				return section.toAddressSection()
			} else if *replacementPrefisLength > BitCount(replacementStartIndex<<segmentToBitsShift) {
				return section.toAddressSection()
			}
		}
	} else if segmentCount == replacedCount {
		if prefixLength == nil || *prefixLength > 0 {
			return replacement
		} else {
			replacementPrefisLength := replacement.GetPrefixLen()
			if replacementPrefisLength != nil && *replacementPrefisLength == 0 { // prefix length is 0
				return replacement
			}
		}
	}

	startBits := BitCount(startIndex << segmentToBitsShift)
	var newPrefixLength PrefixLen
	if prefixLength != nil && *prefixLength <= startBits {
		newPrefixLength = prefixLength
	} else {
		replacementPrefLen := replacement.GetPrefixLen()
		if replacementPrefLen != nil && *replacementPrefLen <= BitCount(replacementEndIndex<<segmentToBitsShift) {
			var replacementPrefixLen BitCount
			replacementStartBits := BitCount(replacementStartIndex << segmentToBitsShift)
			if *replacementPrefLen > replacementStartBits {
				replacementPrefixLen = *replacementPrefLen - replacementStartBits
			}
			newPrefixLength = cacheBitCount(startBits + replacementPrefixLen)
		} else if prefixLength != nil {
			replacementBits := BitCount(replacementCount << segmentToBitsShift)
			var endPrefixBits BitCount
			endIndexBits := BitCount(endIndex << segmentToBitsShift)
			if *prefixLength > endIndexBits {
				endPrefixBits = *prefixLength - endIndexBits
			}
			newPrefixLength = cacheBitCount(startBits + replacementBits + endPrefixBits)
		} else {
			newPrefixLength = nil
		}
	}
	result := section.replace(startIndex, endIndex, replacement, replacementStartIndex, replacementEndIndex, newPrefixLength)
	return result
}

//func (section *addressSectionInternal) IsZeroHost(prefLen BitCount) bool {
//	divCount := section.GetSegmentCount()
//	if divCount == 0 {
//		return false
//	}
//	bytesPerSegment := section.GetBytesPerSegment()
//	bitsPerSegment := section.GetBitsPerSegment()
//	// Note: 1.2.3.4/32 has a zero host
//	prefixedSegmentIndex := getHostSegmentIndex(prefLen, bytesPerSegment, bitsPerSegment)
//	if prefixedSegmentIndex < divCount {
//		segmentPrefixLength := getPrefixedSegmentPrefixLength(bitsPerSegment, prefLen, prefixedSegmentIndex)
//		//if(segmentPrefixLength != nil) {
//		i := prefixedSegmentIndex
//		div := section.GetSegment(i)
//		mask := div.GetSegmentHostMask(*segmentPrefixLength)
//		if div.isMult() || (mask&div.getSegmentValue()) != 0 {
//			return false
//		}
//		i++
//		for ; i < divCount; i++ {
//			div = section.GetSegment(i)
//			if !div.IsZero() {
//				return false
//			}
//		}
//		//}
//	}
//	return true
//}
//
//func (section *addressSectionInternal) IsMaxHost(prefLen BitCount) bool {
//	divCount := section.GetSegmentCount()
//	if divCount == 0 {
//		return false
//	}
//	bytesPerSegment := section.GetBytesPerSegment()
//	bitsPerSegment := section.GetBitsPerSegment()
//	// Note: 1.2.3.4/32 has a zero host
//	prefixedSegmentIndex := getHostSegmentIndex(prefLen, bytesPerSegment, bitsPerSegment)
//	if prefixedSegmentIndex < divCount {
//		segmentPrefixLength := getPrefixedSegmentPrefixLength(bitsPerSegment, prefLen, prefixedSegmentIndex)
//		//if(segmentPrefixLength != nil) {
//		i := prefixedSegmentIndex
//		div := section.GetSegment(i)
//		mask := div.GetSegmentHostMask(*segmentPrefixLength)
//		if div.isMult() || (mask&div.getSegmentValue()) != mask {
//			return false
//		}
//		i++
//		for ; i < divCount; i++ {
//			div = section.GetSegment(i)
//			if !div.IsMax() {
//				return false
//			}
//		}
//		//}
//	}
//	return true
//}
//
//// boundariesOnly: whether we care if the masking works for all values in a range.
//// For instance, 1.2.3.2-4/31 cannot be zero-hosted, because applyng to the boundaries results in 1.2.3.2-4/31,
//// and that includes 1.2.3.3/31 which does not have host of zero.
//// So in that case, we'd normally have IncompatibleAddressError.  boundariesOnly as true avoids the exception,
//// if we are really just interested in getting the zero-host boundaries,
//// and we don't care about the remaining values in-between.
//func (section *addressSectionInternal) createZeroHost(prefLen BitCount, boundariesOnly bool) (*AddressSection, IncompatibleAddressError) {
//	//prefixLength := section.GetPrefixLen() //we know it is prefixed here so no panic on the derefence
//	//xxxxxxx
//	bitsPerSegment := section.GetBitsPerSegment()
//	maxVal := section.GetMaxSegmentValue()
//	//xxx cannot assume ip network xxxx
//	//	mask := section.addrType.getIPNetwork().GetNetworkMask(prefLen)
//	pref := cacheBitCount(prefLen)
//	startIndex := getNetworkSegmentIndex(prefLen, section.GetBytesPerSegment(), section.GetBitsPerSegment())
//	if startIndex < 0 {
//		startIndex = 0
//	}
//	return section.getSubnetSegments(
//		startIndex,
//		cacheBitCount(prefLen),
//		!boundariesOnly, //verifyMask
//		section.getDivision,
//		func(i int) SegInt {
//			segPrefLen := getSegmentPrefixLength(bitsPerSegment, pref, i)
//			if segPrefLen == nil || *segPrefLen >= bitsPerSegment {
//				return section.GetMaxSegmentValue()
//			} else if *segPrefLen <= 0 {
//				return 0
//			}
//			return maxVal & (^SegInt(0) << uint(bitsPerSegment-*segPrefLen))
//		})
//}
//
//func (section *addressSectionInternal) toZeroHost(boundariesOnly bool) (res *AddressSection, err IncompatibleAddressError) {
//	var prefLen BitCount
//	if section.IsPrefixed() {
//		prefLen = *section.GetPrefixLen()
//	} else {
//		prefLen = 0
//	}
//	if section.IsZeroHost(prefLen) {
//		return section.toAddressSection(), nil
//	}
//	//if !section.IsPrefixed() {
//	//	xxx all ones xxxx
//	//	mask := section.addrType.getIPNetwork().GetPrefixedNetworkMask(0)
//	//	res = mask.GetSubSection(0, segmentCount)
//	//	return
//	//}
//	//if section.IncludesZeroHost() && section.IsSingleNetwork() {
//	//	res = section.getLower().ToIPAddressSection() //cached
//	//	return
//	//}
//	return section.createZeroHost(prefLen, boundariesOnly)
//}

func (section *addressSectionInternal) toPrefixBlock() *AddressSection {
	prefixLength := section.GetPrefixLen()
	if prefixLength == nil {
		return section.toAddressSection()
	}
	return section.toPrefixBlockLen(*prefixLength)
}

func (section *addressSectionInternal) toPrefixBlockLen(prefLen BitCount) *AddressSection {
	//bitCountx := section.GetBitCount()
	prefLen = checkSubnet(section.toAddressSection(), prefLen)
	//if prefLen < 0 {
	//	prefLen = 0
	//} else {
	//	if prefLen > bitCount {
	//		prefLen = bitCount
	//	}
	//}
	segCount := section.GetSegmentCount()
	if segCount == 0 {
		return section.toAddressSection()
	}
	segmentByteCount := section.GetBytesPerSegment()
	segmentBitCount := section.GetBitsPerSegment()
	existingPrefixLength := section.GetPrefixLen()
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
	return createSectionMultiple(newSegs, cacheBitCount(prefLen), section.getAddrType(), section.isMultiple() || prefLen < section.GetBitCount())
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
			return createSectionMultiple(newSegs, nil, section.getAddrType(),
				segmentIndex < segCount-1 || lower != upper)
		}
	}
	return section.toAddressSection()
}

func (section *addressSectionInternal) withoutPrefixLen() *AddressSection {
	if !section.IsPrefixed() {
		return section.toAddressSection()
	}
	if sect := section.toIPAddressSection(); sect != nil {
		return sect.withoutPrefixLen().ToAddressSection()
	}
	return createSectionMultiple(section.getDivisionsInternal(), nil, section.getAddrType(), section.isMultiple())
}

func (section *addressSectionInternal) getAdjustedPrefix(adjustment BitCount, floor, ceiling bool) BitCount {
	prefix := section.GetPrefixLen()
	bitCount := section.GetBitCount()
	var result BitCount
	if prefix == nil {
		if adjustment > 0 { // start from 0
			if ceiling && adjustment > bitCount {
				result = bitCount
			} else {
				result = adjustment
			}
		} else { // start from end
			if !floor || -adjustment < bitCount {
				result = bitCount + adjustment
			}
		}
		//prefix = cacheBitCount(section.GetMinPrefixLenForBlock())
	} else {
		result = *prefix + adjustment
		if ceiling && result > bitCount {
			result = bitCount
		} else if floor && result < 0 {
			result = 0
		}
	}
	return result
}

func (section *addressSectionInternal) adjustPrefixLen(adjustment BitCount) *AddressSection {
	// no zeroing
	res, _ := section.adjustPrefixLength(adjustment, false)
	return res
}

func (section *addressSectionInternal) adjustPrefixLenZeroed(adjustment BitCount) (*AddressSection, IncompatibleAddressError) {
	return section.adjustPrefixLength(adjustment, true)
}

func (section *addressSectionInternal) adjustPrefixLength(adjustment BitCount, withZeros bool) (*AddressSection, IncompatibleAddressError) {
	if adjustment == 0 && section.IsPrefixed() {
		return section.toAddressSection(), nil
	}
	prefix := section.getAdjustedPrefix(adjustment, true, true)
	//prefix := section.getAdjustedPrefix(adjustment, true, false)
	//if prefix > section.GetBitCount() {
	//	return removePrefix(zeroed)
	//}
	return section.setPrefixLength(prefix, withZeros)
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
	existingPrefixLength := section.GetPrefixLen()
	if existingPrefixLength != nil && networkPrefixLength == *existingPrefixLength {
		res = section.toAddressSection()
		return
	}
	segmentCount := section.GetSegmentCount()
	var appliedPrefixLen PrefixLen // purposely nil when there are no segments
	verifyMask := false
	var startIndex int
	var segmentMaskProducer func(int) SegInt
	if segmentCount != 0 {
		maxVal := section.GetMaxSegmentValue()
		appliedPrefixLen = cacheBitCount(networkPrefixLength)
		var minPrefIndex, maxPrefIndex int
		var minPrefLen, maxPrefLen BitCount
		bitsPerSegment := section.GetBitsPerSegment()
		bytesPerSegment := section.GetBytesPerSegment()
		prefIndex := getNetworkSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment)
		if existingPrefixLength != nil {
			verifyMask = true
			existingPrefLen := *existingPrefixLength
			existingPrefIndex := getNetworkSegmentIndex(existingPrefLen, bytesPerSegment, bitsPerSegment) // can be -1 if existingPrefLen is 0
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
				segmentMaskProducer = func(i int) SegInt {
					if i >= minPrefIndex {
						if i <= maxPrefIndex {
							minSegPrefLen := *getPrefixedSegmentPrefixLength(bitsPerSegment, minPrefLen, i)
							minMask := maxVal << uint(bitsPerSegment-minSegPrefLen)
							maxSegPrefLen := getPrefixedSegmentPrefixLength(bitsPerSegment, maxPrefLen, i)
							if maxSegPrefLen != nil {
								maxMask := maxVal << uint(bitsPerSegment-*maxSegPrefLen)
								return minMask | ^maxMask
							}
							return minMask
						}
					}
					return maxVal
				}
			} else {
				startIndex = minPrefIndex
				//minPrefIndex = section.GetSegmentCount() // used for zeroing - setting it to the end causes no zeroing
			}
		} else {
			//minPrefIndex = section.GetSegmentCount()
			startIndex = prefIndex
		}
		if segmentMaskProducer == nil {
			segmentMaskProducer = func(i int) SegInt {
				return maxVal
			}
		}
	}
	if startIndex < 0 {
		startIndex = 0
	}

	return section.getSubnetSegments(
		startIndex,
		appliedPrefixLen,
		verifyMask,
		func(i int) *AddressDivision {
			return section.getDivision(i)
		},
		segmentMaskProducer,
	)
}

func (section *addressSectionInternal) assignPrefixForSingleBlock() *AddressSection {
	newPrefix := section.GetPrefixLenForSingleBlock()
	if newPrefix == nil {
		return nil
	}
	newSect := section.setPrefixLen(*newPrefix)
	cache := newSect.cache
	if cache != nil {
		cache.isSinglePrefixBlock = &trueVal
		cache.equivalentPrefix = newPrefix
		cache.minPrefix = newPrefix
	}
	return newSect
}

// Constructs an equivalent address section with the smallest CIDR prefix possible (largest network),
// such that the range of values are a set of subnet blocks for that prefix.
func (section *addressSectionInternal) assignMinPrefixForBlock() *AddressSection {
	return section.setPrefixLen(section.GetMinPrefixLenForBlock())
}

func (section *addressSectionInternal) PrefixEquals(other AddressSectionType) (res bool) {
	o := other.ToAddressSection()
	if section.toAddressSection() == o {
		return true
	} else if section.getAddrType() != o.getAddrType() {
		return
	}
	return section.prefixContains(o, false)
}

func (section *addressSectionInternal) PrefixContains(other AddressSectionType) (res bool) {
	o := other.ToAddressSection()
	if section.toAddressSection() == o {
		return true
	} else if section.getAddrType() != o.getAddrType() {
		return
	}
	return section.prefixContains(o, true)
}

func (section *addressSectionInternal) prefixContains(other *AddressSection, contains bool) (res bool) {
	prefixLength := section.GetPrefixLen()
	var prefixedSection int
	if prefixLength == nil {
		prefixedSection = section.GetSegmentCount()
		if prefixedSection > other.GetSegmentCount() {
			return
		}
	} else {
		prefLen := *prefixLength
		prefixedSection = getNetworkSegmentIndex(prefLen, section.GetBytesPerSegment(), section.GetBitsPerSegment())
		if prefixedSection >= 0 {
			if prefixedSection >= other.GetSegmentCount() {
				return
			}
			one := section.GetSegment(prefixedSection)
			two := other.GetSegment(prefixedSection)
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
		two := other.GetSegment(prefixedSection)
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

func (section *addressSectionInternal) contains(other AddressSectionType) bool {
	if other == nil {
		return true
	}
	otherSection := other.ToAddressSection()
	if section.toAddressSection() == otherSection || otherSection == nil {
		return true
	}
	//check if they are comparable first
	matches, count := section.matchesTypeAndCount(otherSection)
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
	cache := section.cache
	if cache == nil {
		return nil
	}
	return &cache.stringCache
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
	otherOctalPrefix = "0o"
	otherHexPrefix   = "0X"

	//decimalParams            = new(StringOptionsBuilder).SetRadix(10).SetExpandedSegments(true).ToOptions()
	hexParams                  = new(StringOptionsBuilder).SetRadix(16).SetHasSeparator(false).SetExpandedSegments(true).ToOptions()
	hexUppercaseParams         = new(StringOptionsBuilder).SetRadix(16).SetHasSeparator(false).SetExpandedSegments(true).SetUppercase(true).ToOptions()
	hexPrefixedParams          = new(StringOptionsBuilder).SetRadix(16).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(HexPrefix).ToOptions()
	hexPrefixedUppercaseParams = new(StringOptionsBuilder).SetRadix(16).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(HexPrefix).SetUppercase(true).ToOptions()
	octalParams                = new(StringOptionsBuilder).SetRadix(8).SetHasSeparator(false).SetExpandedSegments(true).ToOptions()
	octalPrefixedParams        = new(StringOptionsBuilder).SetRadix(8).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(OctalPrefix).ToOptions()
	octal0oPrefixedParams      = new(StringOptionsBuilder).SetRadix(8).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(otherOctalPrefix).ToOptions()
	binaryParams               = new(StringOptionsBuilder).SetRadix(2).SetHasSeparator(false).SetExpandedSegments(true).ToOptions()
	binaryPrefixedParams       = new(StringOptionsBuilder).SetRadix(2).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(BinaryPrefix).ToOptions()
)

//func (section *addressSectionInternal) GetSegmentStrings() []string {
//	xxx gotta move this func into the 5 subtypes to return nil on nil receiver xxxx
//	return section.getSegmentStrings()
//}

// Format is intentionally the only method with non-pointer receivers.  It is not intended to be called directly, it is intended for use by the fmt package.
// When called by a function in the fmt package, nil values are detected before this method is called, avoiding a panic when calling this method.
func (section addressSectionInternal) Format(state fmt.State, verb rune) {
	section.format(state, verb, NoZone, false)
}

func (section *addressSectionInternal) format(state fmt.State, verb rune, zone Zone, useCanonical bool) {
	if section.hasNoDivisions() {
		state.Write([]byte(nilSection())) //TODO Consider handling the flags, width, precision with this case.
		return
	}
	var str, prefix string
	var err error
	var isNormalized bool

	_, hasPrecision := state.Precision()
	_, hasWidth := state.Width()
	noExtras := !hasPrecision && !hasWidth && zone == NoZone

	switch verb {
	case 's', 'v':
		//TODO see https://cs.opensource.google/go/go/+/refs/tags/go1.17.3:src/fmt/print.go;drc=refs%2Ftags%2Fgo1.17.3;bpv=1;bpt=1;l=570
		// and https://cs.opensource.google/go/go/+/refs/tags/go1.17.3:src/fmt/print.go;drc=refs%2Ftags%2Fgo1.17.3;l=437
		// The latter, fmtString, is used when the arg is a string, using a type switch.
		// But you can see the same method is used on the result of String() when the arg is not a simple ty.
		//WHen not using #v (ie v or s) we defer to fmtStr https://cs.opensource.google/go/go/+/refs/tags/go1.17.3:src/fmt/format.go;drc=refs%2Ftags%2Fgo1.17.3;l=357
		// and this truncates and pads.  Truncate removes the back, based on precision.
		// pads will expand the width to match the given width.
		// So I guess we could do the same.
		// Here are examples: https://cs.opensource.google/go/go/+/refs/tags/go1.17.3:src/fmt/fmt_test.go;l=299;bpv=0;bpt=0

		//TODO 'q' puts quotes around the string https://cs.opensource.google/go/go/+/refs/tags/go1.17.3:src/fmt/fmt_test.go;l=704;bpv=0;bpt=0
		isNormalized = true
		if useCanonical {
			str = section.toCanonicalString()
		} else {
			str = section.toNormalizedString()
		}
	case 'x':
		str, err = section.toHexString(noExtras && state.Flag('#'))
	case 'X':
		withPrefix := noExtras && state.Flag('#')
		if withPrefix {
			str, err = section.toLongStringZoned(NoZone, hexPrefixedUppercaseParams)
		} else {
			str, err = section.toLongStringZoned(NoZone, hexUppercaseParams)
		}
	case 'b':
		str, err = section.toBinaryString(noExtras && state.Flag('#'))
	case 'o':
		str, err = section.toOctalString(noExtras && state.Flag('#'))
	case 'O':
		withPrefix := noExtras
		if withPrefix {
			str, err = section.toLongOctalStringZoned(NoZone, octal0oPrefixedParams)
		} else {
			str, err = section.toLongOctalStringZoned(NoZone, octalParams)
		}
		//str, err = section.toOctalString(noExtras)
	case 'd':
		// TODO LATER decimal strings to replace the inefficient code below, we need large divisions for that because we must go single segment since base not a power of 2, but once we can group into a single large division, we should be good
		bitCount := section.GetBitCount()
		maxDigits := getMaxDigitCountx(10, bitCount, func() int {
			maxVal := bigOne()
			maxVal.Lsh(maxVal, uint(bitCount)+1)
			maxVal.Sub(maxVal, bigOneConst())
			return len(maxVal.Text(10))
		})
		addLeadingZeros := func(str string) string {
			if len(str) < maxDigits {
				zeroCount := maxDigits - len(str)
				var zeros []byte
				for ; zeroCount > 0; zeroCount-- {
					zeros = append(zeros, '0')
				}
				return string(zeros) + str
			}
			return str
		}
		val := section.GetValue()
		valStr := addLeadingZeros(val.Text(10))
		if section.isMultiple() {
			upperVal := section.GetUpperValue()
			upperValStr := addLeadingZeros(upperVal.Text(10))
			str = valStr + RangeSeparatorStr + upperValStr
		} else {
			str = valStr
		}
	default:
		// format not supported
		fmt.Fprintf(state, "%%!%c(address=%s)", verb, section.toString())
		return
	}
	if err != nil { // could not produce an octal, binary, hex or decimal string, so use default instead
		isNormalized = true
		if useCanonical {
			str = section.toCanonicalString()
		} else {
			str = section.toNormalizedString()
		}
	}
	if isNormalized || noExtras {
		state.Write([]byte(str))
		return
	}
	section.writeNumberFmt(state, verb, prefix, str, zone)
}

func (section addressSectionInternal) writeNumberFmt(state fmt.State, verb rune, prefix, str string, zone Zone) {
	if verb == 'O' {
		prefix = otherOctalPrefix // "0o"
	} else if state.Flag('#') {
		switch verb {
		case 'x':
			prefix = HexPrefix
		case 'X':
			prefix = otherHexPrefix
		case 'b':
			prefix = BinaryPrefix
		case 'o':
			prefix = OctalPrefix
		}
	}
	isMulti := section.isMultiple()
	var addrStr, secondStr string
	var separator byte
	if isMulti {
		separatorIndex := len(str) >> 1
		addrStr = str[:separatorIndex]
		separator = str[separatorIndex]
		secondStr = str[separatorIndex+1:]
	} else {
		addrStr = str
	}
	precision, hasPrecision := state.Precision()
	width, hasWidth := state.Width()
	for {
		var zeroCount, leftPaddingCount, rightPaddingCount int
		if hasPrecision {
			if len(addrStr) > precision {
				frontChar := addrStr[0]
				if frontChar == '0' {
					i := 1
					// eliminate leading zeros to match the precision (all the way to nothing)
					for len(addrStr) > precision+i {
						frontChar = addrStr[i]
						if frontChar != '0' {
							break
						}
						i++
					}
					addrStr = addrStr[i:]
				}
			} else if len(addrStr) < precision {
				// expand to match the precision
				zeroCount = precision - len(addrStr)
			}
		}
		length := len(prefix) + zeroCount + len(addrStr) + len(zone)
		if hasWidth && length < width { // padding required
			paddingCount := width - length
			if state.Flag('-') {
				// right padding with spaces (takes precedence over '0' flag)
				rightPaddingCount = paddingCount
			} else if state.Flag('0') && !hasPrecision {
				// left padding with zeros
				zeroCount = paddingCount
			} else {
				// left padding with spaces
				leftPaddingCount = paddingCount
			}
		}

		// left padding/prefix/zeros/str/right padding
		writeBytes(state, ' ', leftPaddingCount)
		writeStr(state, prefix, 1)
		writeBytes(state, '0', zeroCount)
		state.Write([]byte(addrStr))
		state.Write([]byte(zone))
		writeBytes(state, ' ', rightPaddingCount)

		if !isMulti {
			break
		}
		addrStr = secondStr
		isMulti = false
		state.Write([]byte{separator})
	}
}

func writeStr(state fmt.State, str string, count int) {
	if count > 0 && len(str) > 0 {
		bytes := []byte(str)
		for ; count > 0; count-- {
			state.Write(bytes)
		}
	}
}

func writeBytes(state fmt.State, b byte, count int) {
	if count > 0 {
		bytes := make([]byte, count)
		for i := range bytes {
			bytes[i] = b
		}
		state.Write(bytes)
	}
}

func (section *addressSectionInternal) toCanonicalString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToCanonicalString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToCanonicalString()
	} else if sect := section.toMACAddressSection(); sect != nil {
		return sect.ToCanonicalString()
	}
	// zero section
	return nilSection()
}

func (section *addressSectionInternal) toNormalizedString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToNormalizedString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToNormalizedString()
	} else if sect := section.toMACAddressSection(); sect != nil {
		return sect.ToNormalizedString()
	}
	return nilSection()
}

func (section *addressSectionInternal) toCompressedString() string {
	if sect := section.toIPv4AddressSection(); sect != nil {
		return sect.ToCompressedString()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.ToCompressedString()
	} else if sect := section.toMACAddressSection(); sect != nil {
		return sect.ToCompressedString()
	}
	return nilSection()
}

func (section *addressSectionInternal) toHexString(with0xPrefix bool) (string, IncompatibleAddressError) {
	cache := section.getStringCache()
	if cache == nil {
		return section.toHexStringZoned(with0xPrefix, NoZone)
	}
	var cacheField **string
	if with0xPrefix {
		cacheField = &cache.hexStringPrefixed
	} else {
		cacheField = &cache.hexString
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

func (section *addressSectionInternal) toOctalString(with0Prefix bool) (string, IncompatibleAddressError) {
	cache := section.getStringCache()
	if cache == nil {
		return section.toOctalStringZoned(with0Prefix, NoZone)
	}
	var cacheField **string
	if with0Prefix {
		cacheField = &cache.octalStringPrefixed
	} else {
		cacheField = &cache.octalString
	}
	return cacheStrErr(cacheField,
		func() (string, IncompatibleAddressError) {
			return section.toOctalStringZoned(with0Prefix, NoZone)
		})
}

func (section *addressSectionInternal) toOctalStringZoned(with0Prefix bool, zone Zone) (string, IncompatibleAddressError) {
	var opts StringOptions
	if with0Prefix {
		opts = octalPrefixedParams
	} else {
		opts = octalParams
	}
	return section.toLongOctalStringZoned(zone, opts)
}

func (section *addressSectionInternal) toLongOctalStringZoned(zone Zone, opts StringOptions) (string, IncompatibleAddressError) {
	if isDual, err := section.isDualString(); err != nil {
		return "", err
	} else if isDual {
		lowerDivs, _ := section.getLower().createNewDivisions(3)
		upperDivs, _ := section.getUpper().createNewDivisions(3)
		lowerPart := createInitializedGrouping(lowerDivs, nil)
		upperPart := createInitializedGrouping(upperDivs, nil)
		//sect := section.toAddressSection()
		//return toNormalizedStringRange(toParams(params), sect.GetLower(), sect.GetUpper(), zone), nil
		return toNormalizedStringRange(toZonedParams(opts), lowerPart, upperPart, zone), nil
	}
	divs, _ := section.createNewDivisions(3)
	part := createInitializedGrouping(divs, nil)
	return toZonedParams(opts).toZonedString(part, zone), nil
	// see createInitializedGrouping
	//func createInitializedGrouping(divs []*AddressDivision, prefixLength PrefixLen, addrType addrType) *AddressDivisionGrouping {
	//return section.ToCustomString(params), nil
}

/*
protected String toOctalString(boolean with0Prefix, CharSequence zone) throws IncompatibleAddressException {
		if(isDualString()) {
			IPAddressSection lower = getLower();
			IPAddressSection upper = getUpper();
			IPAddressBitsDivision lowerDivs[] = lower.createNewDivisions(3, IPAddressBitsDivision::new, IPAddressBitsDivision[]::new);
			IPAddressStringDivisionSeries lowerPart = new IPAddressDivisionGrouping(lowerDivs, getNetwork());
			IPAddressBitsDivision upperDivs[] = upper.createNewDivisions(3, IPAddressBitsDivision::new, IPAddressBitsDivision[]::new);
			IPAddressStringDivisionSeries upperPart = new IPAddressDivisionGrouping(upperDivs, getNetwork());
			return toNormalizedStringRange(toIPParams(with0Prefix ? IPStringCache.octalPrefixedParams : IPStringCache.octalParams), lowerPart, upperPart, zone);
		}
		IPAddressBitsDivision divs[] = createNewPrefixedDivisions(3, null, null, IPAddressBitsDivision::new, IPAddressBitsDivision[]::new);
		IPAddressStringDivisionSeries part = new IPAddressDivisionGrouping(divs, getNetwork());
		return toIPParams(with0Prefix ? IPStringCache.octalPrefixedParams : IPStringCache.octalParams).toZonedString(part, zone);
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
	return section.ToCustomString(params), nil
}
*/
func (section *addressSectionInternal) toBinaryString(with0bPrefix bool) (string, IncompatibleAddressError) {
	cache := section.getStringCache()
	if cache == nil {
		return section.toBinaryStringZoned(with0bPrefix, NoZone)
	}
	var cacheField **string
	if with0bPrefix {
		cacheField = &cache.binaryStringPrefixed
	} else {
		cacheField = &cache.binaryString
	}
	return cacheStrErr(cacheField,
		func() (string, IncompatibleAddressError) {
			return section.toBinaryStringZoned(with0bPrefix, NoZone)
		})
}

func (section *addressSectionInternal) toBinaryStringZoned(with0bPrefix bool, zone Zone) (string, IncompatibleAddressError) {
	if with0bPrefix {
		return section.toLongStringZoned(zone, binaryPrefixedParams)
	}
	return section.toLongStringZoned(zone, binaryParams)
}

func (section *addressSectionInternal) toLongStringZoned(zone Zone, params StringOptions) (string, IncompatibleAddressError) {
	if isDual, err := section.isDualString(); err != nil {
		return "", err
	} else if isDual {
		sect := section.toAddressSection()
		return toNormalizedStringRange(toZonedParams(params), sect.GetLower(), sect.GetUpper(), zone), nil
	}
	return section.toCustomStringZoned(params, zone), nil
}

func (section *addressSectionInternal) toCustomString(stringOptions StringOptions) string {
	return toNormalizedString(stringOptions, section.toAddressSection())
}

func (section *addressSectionInternal) toCustomStringZoned(stringOptions StringOptions, zone Zone) string {
	return toNormalizedZonedString(stringOptions, section.toAddressSection(), zone)
}

//func (section *addressSectionInternal) toCustomString(stringOptions StringOptions, zone Zone) string {
//	if opts, ok := stringOptions.(IPStringOptions); ok {
//		if sect := section.toAddressSection().ToIPAddressSection(); sect != nil {
//			if ipv6Opts, ok := stringOptions.(IPv6StringOptions); ok {
//				if ipv6Sect := sect.ToIPv6AddressSection(); ipv6Sect != nil {
//					return ipv6Sect.toCustomString(ipv6Opts, zone) xxx the error makes things trickier xxxx
//				}
//			}
//			return sect.ToCustomString(opts)
//		}
//	}
//	return toNormalizedString(stringOptions, section)
//}

func (section *addressSectionInternal) isDualString() (bool, IncompatibleAddressError) {
	count := section.GetSegmentCount()
	if section.isMultiple() {
		//at this point we know we will return true, but we determine now if we must return IncompatibleAddressError
		for i := 0; i < count; i++ {
			division := section.GetSegment(i)
			if division.isMultiple() {
				isLastFull := true
				for j := count - 1; j >= i; j-- {
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
	}
	return false, nil
}

//func (section *addressSectionInternal) GetSegmentStrings() []string {
//	count := section.GetSegmentCount()
//	res := make([]string, count)
//	for i := 0; i < count; i++ {
//		res[i] = section.GetSegment(i).String()
//	}
//	return res
//}

// used by iterator() and nonZeroHostIterator() in section classes
func (section *addressSectionInternal) sectionIterator(excludeFunc func([]*AddressDivision) bool) SectionIterator {
	useOriginal := !section.isMultiple()
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
		if section.GetSegment(i).isMultiple() {
			return true
		}
	}
	return false
}

func (section *addressSectionInternal) isMultipleFrom(segmentCount int) bool {
	segTotal := section.GetSegmentCount()
	for i := segmentCount; i < segTotal; i++ {
		if section.GetSegment(i).isMultiple() {
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
			masker := MaskRange(val64, upperVal64, mask64, seg.GetMaxValue())
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
					masker := MaskRange(val64, upperVal64, mask64, seg.GetMaxValue())
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

//
//
//
//
type AddressSection struct {
	addressSectionInternal
}

func (section *AddressSection) Contains(other AddressSectionType) bool {
	if section == nil {
		return other == nil || other.ToAddressSection() == nil
	}
	return section.contains(other)
}

func (section *AddressSection) Equal(other AddressSectionType) bool {
	if section == nil {
		return other == nil || other.ToAddressSection() == nil
	}
	return section.equal(other)
}

func (section *AddressSection) Compare(item AddressItem) int {
	return CountComparator.Compare(section, item)
}

func (section *AddressSection) CompareSize(other StandardDivisionGroupingType) int {
	if section == nil {
		if other != nil && other.ToAddressDivisionGrouping() != nil {
			// we have size 0, other has size >= 1
			return -1
		}
		return 0
	}
	return section.compareSize(other)
}

func (section *AddressSection) GetCount() *big.Int {
	if section == nil {
		return bigZero()
	} else if sect := section.ToIPv4AddressSection(); sect != nil {
		return sect.GetCount()
	} else if sect := section.ToIPv6AddressSection(); sect != nil {
		return sect.GetCount()
	} else if sect := section.ToMACAddressSection(); sect != nil {
		return sect.GetCount()
	}
	return section.addressDivisionGroupingBase.getCount()
}

func (section *AddressSection) IsMultiple() bool {
	return section != nil && section.isMultiple()
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
	if sect := section.ToIPv4AddressSection(); sect != nil {
		return sect.GetPrefixCountLen(prefixLen)
	} else if sect := section.ToIPv6AddressSection(); sect != nil {
		return sect.GetPrefixCountLen(prefixLen)
	} else if sect := section.ToMACAddressSection(); sect != nil {
		return sect.GetPrefixCountLen(prefixLen)
	}
	return section.addressDivisionGroupingBase.GetPrefixCountLen(prefixLen)
}

// GetBlockCount returns the count of values in the initial (higher) count of divisions.
func (section *AddressSection) GetBlockCount(segmentCount int) *big.Int {
	if sect := section.ToIPv4AddressSection(); sect != nil {
		return sect.GetBlockCount(segmentCount)
	} else if sect := section.ToIPv6AddressSection(); sect != nil {
		return sect.GetBlockCount(segmentCount)
	} else if sect := section.ToMACAddressSection(); sect != nil {
		return sect.GetBlockCount(segmentCount)
	}
	return section.addressDivisionGroupingBase.GetBlockCount(segmentCount)
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
	return section.visitSubDivisions(start, end, func(index int, div *AddressDivision) bool { segs[index] = div.ToAddressSegment(); return false }, len(segs))
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *AddressSection) CopySegments(segs []*AddressSegment) (count int) {
	return section.visitDivisions(func(index int, div *AddressDivision) bool { segs[index] = div.ToAddressSegment(); return false }, len(segs))
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

//func (section *AddressSection) ToZeroHost() (res *AddressSection, err IncompatibleAddressError) {
//	return section.toZeroHost(false)
//}

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

func (section *AddressSection) AdjustPrefixLen(prefixLen BitCount) *AddressSection {
	return section.adjustPrefixLen(prefixLen).ToAddressSection()
}

func (section *AddressSection) AdjustPrefixLenZeroed(prefixLen BitCount) (*AddressSection, IncompatibleAddressError) {
	res, err := section.adjustPrefixLenZeroed(prefixLen)
	return res.ToAddressSection(), err
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

func (section *AddressSection) ToAddressDivisionGrouping() *AddressDivisionGrouping {
	return (*AddressDivisionGrouping)(unsafe.Pointer(section))
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

func (section *AddressSection) Wrap() WrappedAddressSection {
	return WrapSection(section)
}

func (section *AddressSection) Iterator() SectionIterator {
	if section == nil {
		return nilSectIterator()
	}
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

func (section *AddressSection) String() string {
	if section == nil {
		return nilString()
	}
	return section.toString()
}

func (section *AddressSection) ToCanonicalString() string {
	if section == nil {
		return nilString()
	}
	return section.toCanonicalString()
}

func (section *AddressSection) ToNormalizedString() string {
	if section == nil {
		return nilString()
	}
	return section.toNormalizedString()
}

func (section *AddressSection) ToCompressedString() string {
	if section == nil {
		return nilString()
	}
	return section.toCompressedString()
}

func (section *AddressSection) ToHexString(with0xPrefix bool) (string, IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toHexString(with0xPrefix)
}

func (section *AddressSection) ToOctalString(with0Prefix bool) (string, IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toOctalString(with0Prefix)
}

func (section *AddressSection) ToBinaryString(with0bPrefix bool) (string, IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toBinaryString(with0bPrefix)
}

func (section *AddressSection) ToCustomString(stringOptions StringOptions) string {
	if section == nil {
		return nilString()
	}
	return section.toCustomString(stringOptions)
}

func (section *AddressSection) GetSegmentStrings() []string {
	if section == nil {
		return nil
	}
	return section.getSegmentStrings()
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

//func toSegments(
//	bytes []byte,
//	segmentCount int,
//	bytesPerSegment int,
//	bitsPerSegment BitCount,
//	expectedByteCount int,
//	creator addressSegmentCreator,
//	prefixLength PrefixLen) (segments []*AddressDivision, err AddressValueError) {
//
//	//We allow two formats of bytes:
//	//1. two's complement: top bit indicates sign.  Ranging over all 16-byte lengths gives all addresses, from both positive and negative numbers
//	//  Also, we allow sign extension to shorter and longer byte lengths.  For example, -1, -1, -2 is the same as just -2.  So if this were IPv4, we allow -1, -1, -1, -1, -2 and we allow -2.
//	//  This is compatible with BigInteger.  If we have a positive number like 2, we allow 0, 0, 0, 0, 2 and we allow just 2.
//	//  But the top bit must be 0 for 0-sign extension. So if we have 255 as a positive number, we allow 0, 255 but not 255.
//	//  Just 255 is considered negative and equivalent to -1, and extends to -1, -1, -1, -1 or the address 255.255.255.255, not 0.0.0.255
//	//
//	//2. Unsigned values
//	//  We interpret 0, -1, -1, -1, -1 as 255.255.255.255 even though this is not a sign extension of -1, -1, -1, -1.
//	//  In this case, we also allow any 4 byte value to be considered a positive unsigned number, and thus we always allow leading zeros.
//	//  In the case of extending byte array values that are shorter than the required length,
//	//  unsigned values must have a leading zero in cases where the top bit is 1, because the two's complement format takes precedence.
//	//  So the single value 255 must have an additional 0 byte in front to be considered unsigned, as previously shown.
//	//  The single value 255 is considered -1 and is extended to become the address 255.255.255.255,
//	//  but for the unsigned positive value 255 you must use the two bytes 0, 255 which become the address 0.0.0.255.
//	//  Once again, this is compatible with BigInteger.
//	byteLen := len(bytes)
//	missingBytes := expectedByteCount - byteLen
//	startIndex := 0
//
//	//First we handle the situation where we have too many bytes.  Extra bytes can be all zero-bits, or they can be the negative sign extension of all one-bits.
//	if missingBytes < 0 {
//		expectedStartIndex := byteLen - expectedByteCount
//		higherStartIndex := expectedStartIndex - 1
//		expectedExtendedValue := bytes[higherStartIndex]
//		if expectedExtendedValue != 0 {
//			mostSignificantBit := bytes[expectedStartIndex] >> 7
//			if mostSignificantBit != 0 {
//				if expectedExtendedValue != 0xff { //0xff or -1
//					err = &addressValueError{
//						addressError: addressError{key: "ipaddress.error.exceeds.size"},
//						val:          int(expectedExtendedValue),
//					}
//					return
//				}
//			} else {
//				err = &addressValueError{
//					addressError: addressError{key: "ipaddress.error.exceeds.size"},
//					val:          int(expectedExtendedValue),
//				}
//				return
//			}
//		}
//		for startIndex < higherStartIndex {
//			higherStartIndex--
//			if bytes[higherStartIndex] != expectedExtendedValue {
//				err = &addressValueError{
//					addressError: addressError{key: "ipaddress.error.exceeds.size"},
//					val:          int(expectedExtendedValue),
//				}
//				return
//			}
//		}
//		startIndex = expectedStartIndex
//		missingBytes = 0
//	}
//	segments = createSegmentArray(segmentCount)
//	for i, segmentIndex := 0, 0; i < expectedByteCount; segmentIndex++ {
//		var value SegInt
//		k := bytesPerSegment + i
//		j := i
//		if j < missingBytes {
//			mostSignificantBit := bytes[startIndex] >> 7
//			if mostSignificantBit == 0 { //sign extension
//				j = missingBytes
//			} else { //sign extension
//				upper := k
//				if missingBytes < k {
//					upper = missingBytes
//				}
//				for ; j < upper; j++ {
//					value <<= 8
//					value |= 0xff
//				}
//			}
//		}
//		for ; j < k; j++ {
//			byteValue := bytes[startIndex+j-missingBytes]
//			value <<= 8
//			value |= SegInt(byteValue)
//		}
//		i = k
//		segmentPrefixLength := getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex)
//		seg := creator.createSegment(value, value, segmentPrefixLength)
//		segments[segmentIndex] = seg
//	}
//	return
//}

//func toSegments(
//	bytes []byte,
//	segmentCount int,
//	bytesPerSegment int,
//	bitsPerSegment BitCount,
//	expectedByteCount int,
//	creator addressSegmentCreator,
//	prefixLength PrefixLen) (segments []*AddressDivision, err AddressValueError) {
//
//	byteLen := len(bytes)
//	missingBytes := expectedByteCount - byteLen
//	startIndex := 0
//
//	//First we handle the situation where we have too many bytes.  Extra bytes must be all zero-bits.
//	if missingBytes < 0 {
//		expectedStartIndex := byteLen - expectedByteCount
//		higherStartIndex := expectedStartIndex - 1
//		for startIndex < higherStartIndex {
//			higherStartIndex--
//			if bytes[higherStartIndex] != 0 {
//				err = &addressValueError{
//					addressError: addressError{key: "ipaddress.error.exceeds.size"},
//					val:          int(bytes[higherStartIndex]),
//				}
//				return
//			}
//		}
//		startIndex = expectedStartIndex
//		missingBytes = 0
//	}
//	segments = createSegmentArray(segmentCount)
//
//	for i, segmentIndex := 0, 0; i < expectedByteCount; segmentIndex++ {
//		var value SegInt
//		k := bytesPerSegment + i
//		for j := missingBytes; j < k; j++ {
//			byteValue := bytes[startIndex+j-missingBytes]
//			value <<= 8
//			value |= SegInt(byteValue)
//		}
//		i = k
//		segmentPrefixLength := getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex)
//		seg := creator.createSegment(value, value, segmentPrefixLength)
//		segments[segmentIndex] = seg
//	}
//	return
//}

//func toSegments(
//	bytes []byte,
//	segmentCount int,
//	bytesPerSegment int,
//	bitsPerSegment BitCount,
//	creator addressSegmentCreator,
//	prefixLength PrefixLen) (segments []*AddressDivision, err AddressValueError) {
//
//	byteLen := len(bytes)
//	segments = createSegmentArray(segmentCount)
//	for byteIndex, segmentIndex := 0, segmentCount-1; ; segmentIndex-- {
//		var value SegInt
//		k := byteIndex + bytesPerSegment
//		if k > byteLen {
//			k = byteLen
//		}
//		for j := byteIndex; j < k; j++ {
//			byteValue := bytes[j]
//			value <<= 8
//			value |= SegInt(byteValue)
//		}
//		byteIndex = k
//		segmentPrefixLength := getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex)
//		seg := creator.createSegment(value, value, segmentPrefixLength)
//		segments[segmentIndex] = seg
//		if segmentIndex == 0 {
//			// any remaining bytes should be zero
//			for ; byteIndex < byteLen; byteIndex++ {
//				if bytes[byteIndex] != 0 {
//					err = &addressValueError{
//						addressError: addressError{key: "ipaddress.error.exceeds.size"},
//						val:          int(bytes[byteIndex]),
//					}
//					break
//				}
//			}
//			break
//		}
//	}
//	return
//}

func toSegments(
	bytes []byte,
	segmentCount int,
	bytesPerSegment int,
	bitsPerSegment BitCount,
	creator addressSegmentCreator,
	prefixLength PrefixLen) (segments []*AddressDivision, err AddressValueError) {

	segments = createSegmentArray(segmentCount)
	for byteIndex, segmentIndex := len(bytes), segmentCount-1; ; segmentIndex-- {
		var value SegInt
		k := byteIndex - bytesPerSegment
		if k < 0 {
			k = 0
		}
		for j := k; j < byteIndex; j++ {
			byteValue := bytes[j]
			value <<= 8
			value |= SegInt(byteValue)
		}
		byteIndex = k
		segmentPrefixLength := getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex)
		seg := creator.createSegment(value, value, segmentPrefixLength)
		segments[segmentIndex] = seg
		if segmentIndex == 0 {
			// any remaining bytes should be zero
			for byteIndex--; byteIndex >= 0; byteIndex-- {
				if bytes[byteIndex] != 0 {
					err = &addressValueError{
						addressError: addressError{key: "ipaddress.error.exceeds.size"},
						val:          int(bytes[byteIndex]),
					}
					break
				}
			}
			break
		}
	}
	return
}
