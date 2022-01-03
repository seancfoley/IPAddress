//
// Copyright 2020-2022 Sean C Foley
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package ipaddr

import (
	"fmt"
	"math/big"
	"strconv"
	"sync/atomic"
	"unsafe"

	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrerr"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrstr"
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
	result.initMultAndPrefLen() // assigns isMult and checks prefix length
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

func (section *addressSectionInternal) initImplicitPrefLen(bitsPerSegment BitCount) {
	segCount := section.GetSegmentCount()
	if segCount != 0 {
		for i := segCount - 1; i >= 0; i-- {
			segment := section.GetSegment(i)
			minPref := segment.GetMinPrefixLenForBlock()
			if minPref > 0 {
				if minPref != bitsPerSegment || i != segCount-1 {
					section.prefixLength = getNetworkPrefixLen(bitsPerSegment, minPref, i)
				}
				return
			}
		}
		section.prefixLength = cacheBitCount(0)
	}
}

func (section *addressSectionInternal) initMultAndImplicitPrefLen(bitsPerSegment BitCount) {
	segCount := section.GetSegmentCount()
	if segCount != 0 {
		isMultiple := false
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
					if isMultiple { // nothing left to do
						return
					}
				}
			}
			if !isMultiple && segment.isMultiple() {
				isMultiple = true
				section.isMult = true
				if !isBlock { // nothing left to do
					return
				}
			}
		}
		if isBlock {
			section.prefixLength = cacheBitCount(0)
		}
	}
}

// this is used by methods that are used by both mac and ipv4/6, even though the prefix length assignment does not apply to MAC
func (section *addressSectionInternal) initMultAndPrefLen() {
	segCount := section.GetSegmentCount()
	if segCount != 0 {
		var previousSegmentPrefix PrefixLen
		isMultiple := false
		bitsPerSegment := section.GetBitsPerSegment()
		for i := 0; i < segCount; i++ {
			segment := section.GetSegment(i)
			if !isMultiple && segment.isMultiple() {
				isMultiple = true
				section.isMult = true
				if section.prefixLength != nil { // nothing left to do
					break
				}
			}

			//Calculate the segment-level prefix
			//
			//Across an address prefixes are:
			//IPv6: (null):...:(null):(1 to 16):(0):...:(0)
			//or IPv4: ...(null).(1 to 8).(0)...
			//For MAC, all segs have nil prefix since prefix is not segment-level
			segPrefix := segment.getDivisionPrefixLength()
			if previousSegmentPrefix == nil {
				if segPrefix != nil {
					newPref := getNetworkPrefixLen(bitsPerSegment, segPrefix.bitCount(), i)
					section.prefixLength = newPref
					if isMultiple { // nothing left to do
						break
					}
				}
			}
			previousSegmentPrefix = segPrefix
		}
	}
	return
}

func createDivisionsFromSegs(
	segProvider func(index int) *IPAddressSegment,
	segCount int,
	bitsToSegmentShift uint,
	bitsPerSegment BitCount,
	bytesPerSegment int,
	maxValuePerSegment SegInt,
	zeroSeg, zeroSegZeroPrefix, zeroSegPrefixBlock *IPAddressSegment,
	assignedPrefLen PrefixLen) (divs []*AddressDivision, newPref PrefixLen, isMultiple bool) {
	divs = make([]*AddressDivision, segCount)
	var previousSegPrefixed bool
	prefixedSegment := -1
	if assignedPrefLen != nil {
		p := assignedPrefLen.bitCount()
		if p < 0 {
			p = 0
			assignedPrefLen = cacheBitCount(p)
		} else {
			boundaryBits := BitCount(segCount << bitsToSegmentShift)
			if p > boundaryBits {
				p = boundaryBits
				assignedPrefLen = cacheBitCount(p)
			}
		}
		prefixedSegment = getNetworkSegmentIndex(p, bytesPerSegment, bitsPerSegment)
	}
	var lastSegment *IPAddressSegment
	for i := 0; i < segCount; i++ {
		segment := segProvider(i)
		if segment == nil {
			if previousSegPrefixed {
				divs[i] = zeroSegZeroPrefix.ToDiv()
			} else if i == prefixedSegment {
				newPref = cachePrefixLen(assignedPrefLen)
				segPref := getPrefixedSegmentPrefixLength(bitsPerSegment, assignedPrefLen.bitCount(), prefixedSegment)
				if i+1 < segCount && isPrefixSubnet(
					func(segmentIndex int) SegInt {
						seg := segProvider(segmentIndex + i + 1)
						if seg == nil {
							return 0
						}
						return seg.GetSegmentValue()
					},
					func(segmentIndex int) SegInt {
						seg := segProvider(segmentIndex + i + 1)
						if seg == nil {
							return 0
						}
						return seg.GetUpperSegmentValue()
					},
					segCount-(i+1), bytesPerSegment, bitsPerSegment, maxValuePerSegment, 0, zerosOnly) {
					divs[i] = zeroSeg.toPrefixedNetworkDivision(segPref)
					i++
					isMultiple = isMultiple || i < len(divs) || segPref.bitCount() < bitsPerSegment
					for ; i < len(divs); i++ {
						divs[i] = zeroSegPrefixBlock.ToDiv()
					}
					break
				} else {
					divs[i] = zeroSeg.toPrefixedNetworkDivision(segPref)
				}
			} else {
				divs[i] = zeroSeg.ToDiv()
			}
		} else {
			segPrefix := segment.getDivisionPrefixLength()
			segIsPrefixed := segPrefix != nil
			if previousSegPrefixed {
				if !segIsPrefixed || segPrefix.bitCount() != 0 {
					divs[i] = createAddressDivision(
						segment.deriveNewMultiSeg(
							segment.GetSegmentValue(),
							segment.GetUpperSegmentValue(),
							cacheBitCount(0)))
				} else {
					divs[i] = segment.ToDiv()
				}
			} else {
				if i == prefixedSegment || (prefixedSegment > 0 && segIsPrefixed) {
					assignedSegPref := getPrefixedSegmentPrefixLength(bitsPerSegment, assignedPrefLen.bitCount(), prefixedSegment)
					if segIsPrefixed {
						if assignedSegPref == nil || segPrefix.bitCount() < assignedSegPref.bitCount() {
							if segPrefix.bitCount() == 0 && i > 0 {
								// normalize boundaries by looking back
								if !lastSegment.IsPrefixed() {
									divs[i-1] = createAddressDivision(
										lastSegment.deriveNewMultiSeg(
											lastSegment.GetSegmentValue(),
											lastSegment.GetUpperSegmentValue(),
											cacheBitCount(bitsPerSegment)))
								}
							}
							newPref = getNetworkPrefixLen(bitsPerSegment, segPrefix.bitCount(), i)
						} else {
							newPref = cachePrefixLen(assignedPrefLen)
						}
					} else {
						newPref = cachePrefixLen(assignedPrefLen)
					}
					if isPrefixSubnet(
						func(segmentIndex int) SegInt {
							seg := segProvider(segmentIndex)
							if seg == nil {
								return 0
							}
							return seg.GetSegmentValue()
						},
						func(segmentIndex int) SegInt {
							seg := segProvider(segmentIndex)
							if seg == nil {
								return 0
							}
							return seg.GetUpperSegmentValue()
						},
						segCount, bytesPerSegment, bitsPerSegment, maxValuePerSegment, newPref.bitCount(), zerosOnly) {
						divs[i] = segment.toPrefixedNetworkDivision(assignedSegPref)
						i++
						isMultiple = isMultiple || i < len(divs) || newPref.bitCount() < bitsPerSegment
						for ; i < len(divs); i++ {
							divs[i] = zeroSegPrefixBlock.ToDiv()
						}
						break
					}
					previousSegPrefixed = true
				} else if segIsPrefixed {
					if segPrefix.bitCount() == 0 && i > 0 {
						// normalize boundaries by looking back
						if !lastSegment.IsPrefixed() {
							divs[i-1] = createAddressDivision(
								lastSegment.deriveNewMultiSeg(
									lastSegment.GetSegmentValue(),
									lastSegment.GetUpperSegmentValue(),
									cacheBitCount(bitsPerSegment)))
						}
					}
					newPref = getNetworkPrefixLen(bitsPerSegment, segPrefix.bitCount(), i)
					previousSegPrefixed = true
				}
				divs[i] = segment.ToDiv()
			}
			isMultiple = isMultiple || segment.isMultiple()
		}
		lastSegment = segment
	}
	return
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

func (section *addressSectionInternal) equal(otherT AddressSectionType) bool {
	if otherT == nil {
		return false
	}
	other := otherT.ToSectionBase()
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
	return section.getDivision(index).ToSegmentBase()
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
		}
		// we do not want an inconsistency where mac zero length can have prefix len zero while ip sections cannot
		return zeroSection
	}
	if index == 0 && endIndex == thisSegmentCount {
		return section.toAddressSection()
	}
	segs := section.getSubDivisions(index, endIndex)
	newPrefLen := section.getPrefixLen()
	if newPrefLen != nil {
		newPrefLen = getAdjustedPrefixLength(section.GetBitsPerSegment(), newPrefLen.bitCount(), index, endIndex)
	}
	addrType := section.getAddrType()
	if !section.isMultiple() {
		return createSection(segs, newPrefLen, addrType)
	}
	return createInitializedSection(segs, newPrefLen, addrType)
}

func (section *addressSectionInternal) copySegmentsToSlice(divs []*AddressDivision) (count int) {
	return section.copyDivisions(divs)
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
		lowSegs[i] = seg.GetLower().ToDiv()
		if highSegs != nil {
			highSegs[i] = seg.GetUpper().ToDiv()
		}
	}
	lower = deriveAddressSection(section.toAddressSection(), lowSegs)
	if highSegs == nil {
		upper = lower
	} else {
		upper = deriveAddressSection(section.toAddressSection(), highSegs)
	}
	return
}

func (section *addressSectionInternal) reverseSegments(segProducer func(int) (*AddressSegment, addrerr.IncompatibleAddressError)) (res *AddressSection, err addrerr.IncompatibleAddressError) {
	count := section.GetSegmentCount()
	if count == 0 { // case count == 1 we cannot exit early, we need to apply segProducer to each segment
		if section.isPrefixed() {
			return section.withoutPrefixLen(), nil
		}
		return section.toAddressSection(), nil
	}
	newSegs := createSegmentArray(count)
	halfCount := count >> 1
	i := 0
	isSame := !section.isPrefixed() //when reversing, the prefix must go
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
		newSegs[j] = newj.ToDiv()
		newSegs[i] = newi.ToDiv()
		if isSame &&
			!(segValsSame(newi.getSegmentValue(), origi.getSegmentValue(), newi.getUpperSegmentValue(), origi.getUpperSegmentValue()) &&
				segValsSame(newj.getSegmentValue(), origj.getSegmentValue(), newj.getUpperSegmentValue(), origj.getUpperSegmentValue())) {
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
}

func (section *addressSectionInternal) reverseBits(perByte bool) (res *AddressSection, err addrerr.IncompatibleAddressError) {
	if perByte {
		isSame := !section.isPrefixed() //when reversing, the prefix must go
		count := section.GetSegmentCount()
		newSegs := createSegmentArray(count)
		for i := 0; i < count; i++ {
			seg := section.GetSegment(i)
			var reversedSeg *AddressSegment
			reversedSeg, err = seg.ReverseBits(perByte)
			if err != nil {
				return
			}
			newSegs[i] = reversedSeg.ToDiv()
			if isSame && !segValsSame(seg.getSegmentValue(), reversedSeg.getSegmentValue(), seg.getUpperSegmentValue(), reversedSeg.getUpperSegmentValue()) {
				isSame = false
			}
		}
		if isSame {
			res = section.toAddressSection() //We can do this because for ipv6 startIndex stays the same and for mac startIndex and extended stays the same
			return
		}
		res = deriveAddressSectionPrefLen(section.toAddressSection(), newSegs, nil)
		return
	}
	return section.reverseSegments(
		func(i int) (*AddressSegment, addrerr.IncompatibleAddressError) {
			return section.GetSegment(i).ReverseBits(perByte)
		},
	)
}

func (section *addressSectionInternal) reverseBytes(perSegment bool) (res *AddressSection, err addrerr.IncompatibleAddressError) {
	if perSegment {
		isSame := !section.isPrefixed() //when reversing, the prefix must go
		count := section.GetSegmentCount()
		newSegs := createSegmentArray(count)
		for i := 0; i < count; i++ {
			seg := section.GetSegment(i)
			var reversedSeg *AddressSegment
			reversedSeg, err = seg.ReverseBytes()
			if err != nil {
				return
			}
			newSegs[i] = reversedSeg.ToDiv()
			if isSame && !segValsSame(seg.getSegmentValue(), reversedSeg.getSegmentValue(), seg.getUpperSegmentValue(), reversedSeg.getUpperSegmentValue()) {
				isSame = false
			}
		}
		if isSame {
			res = section.toAddressSection() //We can do this because for ipv6 startIndex stays the same and for mac startIndex and extended stays the same
			return
		}
		res = deriveAddressSectionPrefLen(section.toAddressSection(), newSegs, nil)
		return
	}
	return section.reverseSegments(
		func(i int) (*AddressSegment, addrerr.IncompatibleAddressError) {
			return section.GetSegment(i).ReverseBytes()
		},
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
}

// Replaces segments starting from startIndex and ending before endIndex with the segments starting at replacementStartIndex and
//ending before replacementEndIndex from the replacement section
func (section *addressSectionInternal) replaceLen(startIndex, endIndex int, replacement *AddressSection, replacementStartIndex, replacementEndIndex int, segmentToBitsShift uint) *AddressSection {
	segmentCount := section.GetSegmentCount()
	startIndex, endIndex, replacementStartIndex, replacementEndIndex =
		adjustIndices(startIndex, endIndex, segmentCount, replacementStartIndex, replacementEndIndex, replacement.GetSegmentCount())

	replacedCount := endIndex - startIndex
	replacementCount := replacementEndIndex - replacementStartIndex

	// unlike ipvx, sections of zero length with 0 prefix are still considered to be applying their prefix during replacement,
	// because you can have zero length prefixes when there are no bits in the section
	prefixLength := section.getPrefixLen()
	if replacementCount == 0 && replacedCount == 0 {
		if prefixLength != nil {
			prefLen := prefixLength.bitCount()
			if prefLen <= BitCount(startIndex<<segmentToBitsShift) {
				return section.toAddressSection()
			} else {
				replacementPrefisLength := replacement.getPrefixLen()
				if replacementPrefisLength == nil {
					return section.toAddressSection()
				} else if replacementPrefisLength.bitCount() > BitCount(replacementStartIndex<<segmentToBitsShift) {
					return section.toAddressSection()
				}
			}
		} else {
			replacementPrefisLength := replacement.getPrefixLen()
			if replacementPrefisLength == nil {
				return section.toAddressSection()
			} else if replacementPrefisLength.bitCount() > BitCount(replacementStartIndex<<segmentToBitsShift) {
				return section.toAddressSection()
			}
		}
	} else if segmentCount == replacedCount {
		if prefixLength == nil || prefixLength.bitCount() > 0 {
			return replacement
		} else {
			replacementPrefisLength := replacement.getPrefixLen()
			if replacementPrefisLength != nil && replacementPrefisLength.bitCount() == 0 { // prefix length is 0
				return replacement
			}
		}
	}

	startBits := BitCount(startIndex << segmentToBitsShift)
	var newPrefixLength PrefixLen
	if prefixLength != nil && prefixLength.bitCount() <= startBits {
		newPrefixLength = prefixLength
	} else {
		replacementPrefLen := replacement.getPrefixLen()
		if replacementPrefLen != nil && replacementPrefLen.bitCount() <= BitCount(replacementEndIndex<<segmentToBitsShift) {
			var replacementPrefixLen BitCount
			replacementStartBits := BitCount(replacementStartIndex << segmentToBitsShift)
			if replacementPrefLen.bitCount() > replacementStartBits {
				replacementPrefixLen = replacementPrefLen.bitCount() - replacementStartBits
			}
			newPrefixLength = cacheBitCount(startBits + replacementPrefixLen)
		} else if prefixLength != nil {
			replacementBits := BitCount(replacementCount << segmentToBitsShift)
			var endPrefixBits BitCount
			endIndexBits := BitCount(endIndex << segmentToBitsShift)
			if prefixLength.bitCount() > endIndexBits {
				endPrefixBits = prefixLength.bitCount() - endIndexBits
			}
			newPrefixLength = cacheBitCount(startBits + replacementBits + endPrefixBits)
		} else {
			newPrefixLength = nil
		}
	}
	result := section.replace(startIndex, endIndex, replacement, replacementStartIndex, replacementEndIndex, newPrefixLength)
	return result
}

func (section *addressSectionInternal) toPrefixBlock() *AddressSection {
	prefixLength := section.getPrefixLen()
	if prefixLength == nil {
		return section.toAddressSection()
	}
	return section.toPrefixBlockLen(prefixLength.bitCount())
}

func (section *addressSectionInternal) toPrefixBlockLen(prefLen BitCount) *AddressSection {
	prefLen = checkSubnet(section.toAddressSection(), prefLen)
	segCount := section.GetSegmentCount()
	if segCount == 0 {
		return section.toAddressSection()
	}
	segmentByteCount := section.GetBytesPerSegment()
	segmentBitCount := section.GetBitsPerSegment()
	existingPrefixLength := section.getPrefixLen()
	prefixMatches := existingPrefixLength != nil && existingPrefixLength.bitCount() == prefLen
	if prefixMatches {
		prefixedSegmentIndex := getHostSegmentIndex(prefLen, segmentByteCount, segmentBitCount)
		if prefixedSegmentIndex >= segCount {
			return section.toAddressSection()
		}
		segPrefLength := getPrefixedSegmentPrefixLength(segmentBitCount, prefLen, prefixedSegmentIndex).bitCount()
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
	if !section.isPrefixed() {
		return section.toAddressSection()
	}
	if sect := section.toIPAddressSection(); sect != nil {
		return sect.withoutPrefixLen().ToSectionBase()
	}
	return createSectionMultiple(section.getDivisionsInternal(), nil, section.getAddrType(), section.isMultiple())
}

func (section *addressSectionInternal) getAdjustedPrefix(adjustment BitCount, floor, ceiling bool) BitCount {
	prefix := section.getPrefixLen()
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
	} else {
		result = prefix.bitCount() + adjustment
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

func (section *addressSectionInternal) adjustPrefixLenZeroed(adjustment BitCount) (*AddressSection, addrerr.IncompatibleAddressError) {
	return section.adjustPrefixLength(adjustment, true)
}

func (section *addressSectionInternal) adjustPrefixLength(adjustment BitCount, withZeros bool) (*AddressSection, addrerr.IncompatibleAddressError) {
	if adjustment == 0 && section.isPrefixed() {
		return section.toAddressSection(), nil
	}
	prefix := section.getAdjustedPrefix(adjustment, true, true)
	return section.setPrefixLength(prefix, withZeros)
}

func (section *addressSectionInternal) setPrefixLen(prefixLen BitCount) *AddressSection {
	// no zeroing
	res, _ := section.setPrefixLength(prefixLen, false)
	return res
}

func (section *addressSectionInternal) setPrefixLenZeroed(prefixLen BitCount) (*AddressSection, addrerr.IncompatibleAddressError) {
	return section.setPrefixLength(prefixLen, true)
}

func (section *addressSectionInternal) setPrefixLength(
	networkPrefixLength BitCount,
	withZeros bool,
) (res *AddressSection, err addrerr.IncompatibleAddressError) {
	existingPrefixLength := section.getPrefixLen()
	if existingPrefixLength != nil && networkPrefixLength == existingPrefixLength.bitCount() {
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
			existingPrefLen := existingPrefixLength.bitCount()
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
							minSegPrefLen := getPrefixedSegmentPrefixLength(bitsPerSegment, minPrefLen, i).bitCount()
							minMask := maxVal << uint(bitsPerSegment-minSegPrefLen)
							maxSegPrefLen := getPrefixedSegmentPrefixLength(bitsPerSegment, maxPrefLen, i)
							if maxSegPrefLen != nil {
								maxMask := maxVal << uint(bitsPerSegment-maxSegPrefLen.bitCount())
								return minMask | ^maxMask
							}
							return minMask
						}
					}
					return maxVal
				}
			} else {
				startIndex = minPrefIndex
			}
		} else {
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
	newSect := section.setPrefixLen(newPrefix.bitCount())
	cache := newSect.cache
	if cache != nil {
		// no atomic writes required since we created this new section in here
		cache.isSinglePrefixBlock = &trueVal
		cache.equivalentPrefix = cachePrefix(newPrefix.bitCount())
		cache.minPrefix = newPrefix
	}
	return newSect
}

// Constructs an equivalent address section with the smallest CIDR prefix possible (largest network),
// such that the range of values are a set of subnet blocks for that prefix.
func (section *addressSectionInternal) assignMinPrefixForBlock() *AddressSection {
	return section.setPrefixLen(section.GetMinPrefixLenForBlock())
}

func (section *addressSectionInternal) PrefixEqual(other AddressSectionType) (res bool) {
	o := other.ToSectionBase()
	if section.toAddressSection() == o {
		return true
	} else if section.getAddrType() != o.getAddrType() {
		return
	}
	return section.prefixContains(o, false)
}

func (section *addressSectionInternal) PrefixContains(other AddressSectionType) (res bool) {
	o := other.ToSectionBase()
	if section.toAddressSection() == o {
		return true
	} else if section.getAddrType() != o.getAddrType() {
		return
	}
	return section.prefixContains(o, true)
}

func (section *addressSectionInternal) prefixContains(other *AddressSection, contains bool) (res bool) {
	prefixLength := section.getPrefixLen()
	var prefixedSection int
	if prefixLength == nil {
		prefixedSection = section.GetSegmentCount()
		if prefixedSection > other.GetSegmentCount() {
			return
		}
	} else {
		prefLen := prefixLength.bitCount()
		prefixedSection = getNetworkSegmentIndex(prefLen, section.GetBytesPerSegment(), section.GetBitsPerSegment())
		if prefixedSection >= 0 {
			if prefixedSection >= other.GetSegmentCount() {
				return
			}
			one := section.GetSegment(prefixedSection)
			two := other.GetSegment(prefixedSection)
			segPrefixLength := getPrefixedSegmentPrefixLength(one.getBitCount(), prefLen, prefixedSection)
			if contains {
				if !one.PrefixContains(two, segPrefixLength.bitCount()) {
					return
				}
			} else {
				if !one.PrefixEqual(two, segPrefixLength.bitCount()) {
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
	otherSection := other.ToSectionBase()
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
		if !div.ContainsPrefixBlock(segmentPrefixLength.bitCount()) {
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
		return sect.Increment(increment).ToSectionBase()
	} else if sect := section.toIPv6AddressSection(); sect != nil {
		return sect.Increment(increment).ToSectionBase()
	} else if sect := section.toMACAddressSection(); sect != nil {
		return sect.Increment(increment).ToSectionBase()
	}
	return nil
}

var (
	otherOctalPrefix = "0o"
	otherHexPrefix   = "0X"

	//decimalParams            = new(StringOptionsBuilder).SetRadix(10).SetExpandedSegments(true).ToOptions()
	hexParams                  = new(addrstr.StringOptionsBuilder).SetRadix(16).SetHasSeparator(false).SetExpandedSegments(true).ToOptions()
	hexUppercaseParams         = new(addrstr.StringOptionsBuilder).SetRadix(16).SetHasSeparator(false).SetExpandedSegments(true).SetUppercase(true).ToOptions()
	hexPrefixedParams          = new(addrstr.StringOptionsBuilder).SetRadix(16).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(HexPrefix).ToOptions()
	hexPrefixedUppercaseParams = new(addrstr.StringOptionsBuilder).SetRadix(16).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(HexPrefix).SetUppercase(true).ToOptions()
	octalParams                = new(addrstr.StringOptionsBuilder).SetRadix(8).SetHasSeparator(false).SetExpandedSegments(true).ToOptions()
	octalPrefixedParams        = new(addrstr.StringOptionsBuilder).SetRadix(8).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(OctalPrefix).ToOptions()
	octal0oPrefixedParams      = new(addrstr.StringOptionsBuilder).SetRadix(8).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(otherOctalPrefix).ToOptions()
	binaryParams               = new(addrstr.StringOptionsBuilder).SetRadix(2).SetHasSeparator(false).SetExpandedSegments(true).ToOptions()
	binaryPrefixedParams       = new(addrstr.StringOptionsBuilder).SetRadix(2).SetHasSeparator(false).SetExpandedSegments(true).SetAddressLabel(BinaryPrefix).ToOptions()
)

// Format is intentionally the only method with non-pointer receivers.  It is not intended to be called directly, it is intended for use by the fmt package.
// When called by a function in the fmt package, nil values are detected before this method is called, avoiding a panic when calling this method.
func (section addressSectionInternal) Format(state fmt.State, verb rune) {
	section.format(state, verb, NoZone, false)
}

func (section *addressSectionInternal) format(state fmt.State, verb rune, zone Zone, useCanonical bool) {
	var str string
	var err error
	var isStringFormat bool

	_, hasPrecision := state.Precision()
	_, hasWidth := state.Width()
	useDefaultStr := !hasPrecision && !hasWidth
	switch verb {
	case 's', 'v', 'q':
		isStringFormat = true
		if useCanonical {
			if zone != NoZone {
				str = section.toAddressSection().ToIPv6().toCanonicalString(zone)
			} else {
				str = section.toCanonicalString()
			}
		} else {
			if zone != NoZone {
				str = section.toAddressSection().ToIPv6().toNormalizedString(zone)
			} else {
				str = section.toNormalizedString()
			}
		}
		if verb == 'q' && useDefaultStr {
			if state.Flag('#') && (zone == NoZone || strconv.CanBackquote(string(zone))) {
				str = "`" + str + "`"
			} else if zone == NoZone {
				str = `"` + str + `"`
			} else {
				str = strconv.Quote(str) // zones should not have special characters, but you cannot be sure
			}
		}
	case 'x':
		useDefaultStr = useDefaultStr && zone == NoZone
		str, err = section.toHexString(useDefaultStr && state.Flag('#'))
	case 'X':
		useDefaultStr = useDefaultStr && zone == NoZone
		if useDefaultStr && state.Flag('#') {
			str, err = section.toLongStringZoned(NoZone, hexPrefixedUppercaseParams)
		} else {
			str, err = section.toLongStringZoned(NoZone, hexUppercaseParams)
		}
	case 'b':
		useDefaultStr = useDefaultStr && zone == NoZone
		str, err = section.toBinaryString(useDefaultStr && state.Flag('#'))
	case 'o':
		useDefaultStr = useDefaultStr && zone == NoZone
		str, err = section.toOctalString(useDefaultStr && state.Flag('#'))
	case 'O':
		useDefaultStr = useDefaultStr && zone == NoZone
		if useDefaultStr {
			str, err = section.toLongOctalStringZoned(NoZone, octal0oPrefixedParams)
		} else {
			str, err = section.toLongOctalStringZoned(NoZone, octalParams)
		}
	case 'd':
		// TODO LATER decimal strings to replace the less efficient code below, we need large divisions for that because we must go single segment since base not a power of 2, but once we can group into a single large division, we should be good
		if !section.hasNoDivisions() {
			bitCount := section.GetBitCount()
			maxDigits := getMaxDigitCountCalc(10, bitCount, func() int {
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
		}
	default:
		// format not supported
		_, _ = fmt.Fprintf(state, "%%!%c(address=%s)", verb, section.toString())
		return
	}
	if err != nil { // could not produce an octal, binary, hex or decimal string, so use string format instead
		isStringFormat = true
		if useCanonical {
			str = section.toCanonicalString()
		} else {
			str = section.toNormalizedString()
		}
	}
	if useDefaultStr {
		_, _ = state.Write([]byte(str))
	} else if isStringFormat {
		section.writeStrFmt(state, verb, str, zone)
	} else {
		section.writeNumberFmt(state, verb, str, zone)
	}
}

func (section addressSectionInternal) writeStrFmt(state fmt.State, verb rune, str string, zone Zone) {
	if precision, hasPrecision := state.Precision(); hasPrecision && len(str) > precision {
		str = str[:precision]
	}
	if verb == 'q' {
		if state.Flag('#') && (zone == NoZone || strconv.CanBackquote(string(zone))) {
			str = "`" + str + "`"
		} else if zone == NoZone {
			str = `"` + str + `"`
		} else {
			str = strconv.Quote(str) // zones should not have special characters, but you cannot be sure
		}
	}
	var leftPaddingCount, rightPaddingCount int
	if width, hasWidth := state.Width(); hasWidth && len(str) < width { // padding required
		paddingCount := width - len(str)
		if state.Flag('-') {
			// right padding with spaces (takes precedence over '0' flag)
			rightPaddingCount = paddingCount
		} else {
			// left padding with spaces
			leftPaddingCount = paddingCount
		}
	}
	// left padding/str/right padding
	writeBytes(state, ' ', leftPaddingCount)
	_, _ = state.Write([]byte(str))
	writeBytes(state, ' ', rightPaddingCount)
}

func (section addressSectionInternal) writeNumberFmt(state fmt.State, verb rune, str string, zone Zone) {
	var prefix string
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
	usePrecision := hasPrecision
	if section.hasNoDivisions() {
		usePrecision = false
		prefix = ""
	}
	for {
		var zeroCount, leftPaddingCount, rightPaddingCount int
		if usePrecision {
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
		length := len(prefix) + zeroCount + len(addrStr)
		zoneRequired := len(zone) > 0
		if zoneRequired {
			length += len(zone) + 1
		}
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
		_, _ = state.Write([]byte(addrStr))
		if zoneRequired {
			_, _ = state.Write([]byte{IPv6ZoneSeparator})
			_, _ = state.Write([]byte(zone))
		}
		writeBytes(state, ' ', rightPaddingCount)

		if !isMulti {
			break
		}
		addrStr = secondStr
		isMulti = false
		_, _ = state.Write([]byte{separator})
	}
}

func writeStr(state fmt.State, str string, count int) {
	if count > 0 && len(str) > 0 {
		bytes := []byte(str)
		for ; count > 0; count-- {
			_, _ = state.Write(bytes)
		}
	}
}

func writeBytes(state fmt.State, b byte, count int) {
	if count > 0 {
		bytes := make([]byte, count)
		for i := range bytes {
			bytes[i] = b
		}
		_, _ = state.Write(bytes)
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

func (section *addressSectionInternal) toHexString(with0xPrefix bool) (string, addrerr.IncompatibleAddressError) {
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
		func() (string, addrerr.IncompatibleAddressError) {
			return section.toHexStringZoned(with0xPrefix, NoZone)
		})
}

func (section *addressSectionInternal) toHexStringZoned(with0xPrefix bool, zone Zone) (string, addrerr.IncompatibleAddressError) {
	if with0xPrefix {
		return section.toLongStringZoned(zone, hexPrefixedParams)
	}
	return section.toLongStringZoned(zone, hexParams)
}

func (section *addressSectionInternal) toOctalString(with0Prefix bool) (string, addrerr.IncompatibleAddressError) {
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
		func() (string, addrerr.IncompatibleAddressError) {
			return section.toOctalStringZoned(with0Prefix, NoZone)
		})
}

func (section *addressSectionInternal) toOctalStringZoned(with0Prefix bool, zone Zone) (string, addrerr.IncompatibleAddressError) {
	var opts addrstr.StringOptions
	if with0Prefix {
		opts = octalPrefixedParams
	} else {
		opts = octalParams
	}
	return section.toLongOctalStringZoned(zone, opts)
}

func (section *addressSectionInternal) toLongOctalStringZoned(zone Zone, opts addrstr.StringOptions) (string, addrerr.IncompatibleAddressError) {
	if isDual, err := section.isDualString(); err != nil {
		return "", err
	} else if isDual {
		lowerDivs, _ := section.getLower().createNewDivisions(3)
		upperDivs, _ := section.getUpper().createNewDivisions(3)
		lowerPart := createInitializedGrouping(lowerDivs, nil)
		upperPart := createInitializedGrouping(upperDivs, nil)
		return toNormalizedStringRange(toZonedParams(opts), lowerPart, upperPart, zone), nil
	}
	divs, _ := section.createNewDivisions(3)
	part := createInitializedGrouping(divs, nil)
	return toZonedParams(opts).toZonedString(part, zone), nil
}

func (section *addressSectionInternal) toBinaryString(with0bPrefix bool) (string, addrerr.IncompatibleAddressError) {
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
		func() (string, addrerr.IncompatibleAddressError) {
			return section.toBinaryStringZoned(with0bPrefix, NoZone)
		})
}

func (section *addressSectionInternal) toBinaryStringZoned(with0bPrefix bool, zone Zone) (string, addrerr.IncompatibleAddressError) {
	if with0bPrefix {
		return section.toLongStringZoned(zone, binaryPrefixedParams)
	}
	return section.toLongStringZoned(zone, binaryParams)
}

func (section *addressSectionInternal) toLongStringZoned(zone Zone, params addrstr.StringOptions) (string, addrerr.IncompatibleAddressError) {
	if isDual, err := section.isDualString(); err != nil {
		return "", err
	} else if isDual {
		sect := section.toAddressSection()
		return toNormalizedStringRange(toZonedParams(params), sect.GetLower(), sect.GetUpper(), zone), nil
	}
	return section.toCustomStringZoned(params, zone), nil
}

func (section *addressSectionInternal) toCustomString(stringOptions addrstr.StringOptions) string {
	return toNormalizedString(stringOptions, section.toAddressSection())
}

func (section *addressSectionInternal) toCustomStringZoned(stringOptions addrstr.StringOptions, zone Zone) string {
	return toNormalizedZonedString(stringOptions, section.toAddressSection(), zone)
}

func (section *addressSectionInternal) isDualString() (bool, addrerr.IncompatibleAddressError) {
	count := section.GetSegmentCount()
	if section.isMultiple() {
		//at this point we know we will return true, but we determine now if we must returnaddrerr.IncompatibleAddressError
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
	prefLength := prefLen.bitCount()
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
) (res *AddressSection, err addrerr.IncompatibleAddressError) {
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
	return section.toAddressSection().ToIP()
}

func (section *addressSectionInternal) toIPv4AddressSection() *IPv4AddressSection {
	return section.toAddressSection().ToIPv4()
}

func (section *addressSectionInternal) toIPv6AddressSection() *IPv6AddressSection {
	return section.toAddressSection().ToIPv6()
}

func (section *addressSectionInternal) toMACAddressSection() *MACAddressSection {
	return section.toAddressSection().ToMAC()
}

//// only needed for godoc / pkgsite

func (section *addressSectionInternal) IsZero() bool {
	return section.addressDivisionGroupingInternal.IsZero()
}

func (section *addressSectionInternal) IncludesZero() bool {
	return section.addressDivisionGroupingInternal.IncludesZero()
}

func (section *addressSectionInternal) IsMax() bool {
	return section.addressDivisionGroupingInternal.IsMax()
}

func (section *addressSectionInternal) IncludesMax() bool {
	return section.addressDivisionGroupingInternal.IncludesMax()
}

func (section *addressSectionInternal) IsFullRange() bool {
	return section.addressDivisionGroupingInternal.IsFullRange()
}

func (section *addressSectionInternal) GetSequentialBlockIndex() int {
	return section.addressDivisionGroupingInternal.GetSequentialBlockIndex()
}

func (section *addressSectionInternal) GetPrefixLen() PrefixLen {
	return section.addressDivisionGroupingInternal.GetPrefixLen()
}

func (section *addressSectionInternal) ContainsSinglePrefixBlock(prefixLen BitCount) bool {
	return section.addressDivisionGroupingInternal.ContainsSinglePrefixBlock(prefixLen)
}

func (section *addressSectionInternal) IsPrefixBlock() bool {
	return section.addressDivisionGroupingInternal.IsPrefixBlock()
}

func (section *addressSectionInternal) IsSinglePrefixBlock() bool {
	return section.addressDivisionGroupingInternal.IsSinglePrefixBlock()
}

func (section *addressSectionInternal) GetMinPrefixLenForBlock() BitCount {
	return section.addressDivisionGroupingInternal.GetMinPrefixLenForBlock()
}

func (section *addressSectionInternal) GetPrefixLenForSingleBlock() PrefixLen {
	return section.addressDivisionGroupingInternal.GetPrefixLenForSingleBlock()
}

func (section *addressSectionInternal) GetValue() *big.Int {
	return section.addressDivisionGroupingInternal.GetValue()
}

func (section *addressSectionInternal) GetUpperValue() *big.Int {
	return section.addressDivisionGroupingInternal.GetUpperValue()
}

func (section *addressSectionInternal) Bytes() []byte {
	return section.addressDivisionGroupingInternal.Bytes()
}

func (section *addressSectionInternal) UpperBytes() []byte {
	return section.addressDivisionGroupingInternal.UpperBytes()
}

func (section *addressSectionInternal) CopyBytes(bytes []byte) []byte {
	return section.addressDivisionGroupingInternal.CopyBytes(bytes)
}

func (section *addressSectionInternal) CopyUpperBytes(bytes []byte) []byte {
	return section.addressDivisionGroupingInternal.CopyUpperBytes(bytes)
}

func (section *addressSectionInternal) IsSequential() bool {
	return section.addressDivisionGroupingInternal.IsSequential()
}

//// end needed for godoc / pkgsite

//
//
//
//
type AddressSection struct {
	addressSectionInternal
}

func (section *AddressSection) Contains(other AddressSectionType) bool {
	if section == nil {
		return other == nil || other.ToSectionBase() == nil
	}
	return section.contains(other)
}

func (section *AddressSection) Equal(other AddressSectionType) bool {
	if section == nil {
		return other == nil || other.ToSectionBase() == nil
	}
	return section.equal(other)
}

func (section *AddressSection) Compare(item AddressItem) int {
	return CountComparator.Compare(section, item)
}

func (section *AddressSection) CompareSize(other StandardDivGroupingType) int {
	if section == nil {
		if other != nil && other.ToDivGrouping() != nil {
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
	} else if sect := section.ToIPv4(); sect != nil {
		return sect.GetCount()
	} else if sect := section.ToIPv6(); sect != nil {
		return sect.GetCount()
	} else if sect := section.ToMAC(); sect != nil {
		return sect.GetCount()
	}
	return section.addressDivisionGroupingBase.getCount()
}

func (section *AddressSection) IsMultiple() bool {
	return section != nil && section.isMultiple()
}

func (section *AddressSection) GetPrefixCount() *big.Int {
	if sect := section.ToIPv4(); sect != nil {
		return sect.GetPrefixCount()
	} else if sect := section.ToIPv6(); sect != nil {
		return sect.GetPrefixCount()
	} else if sect := section.ToMAC(); sect != nil {
		return sect.GetPrefixCount()
	}
	return section.addressDivisionGroupingBase.GetPrefixCount()
}

func (section *AddressSection) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	if sect := section.ToIPv4(); sect != nil {
		return sect.GetPrefixCountLen(prefixLen)
	} else if sect := section.ToIPv6(); sect != nil {
		return sect.GetPrefixCountLen(prefixLen)
	} else if sect := section.ToMAC(); sect != nil {
		return sect.GetPrefixCountLen(prefixLen)
	}
	return section.addressDivisionGroupingBase.GetPrefixCountLen(prefixLen)
}

// GetBlockCount returns the count of values in the initial (higher) count of divisions.
func (section *AddressSection) GetBlockCount(segmentCount int) *big.Int {
	if sect := section.ToIPv4(); sect != nil {
		return sect.GetBlockCount(segmentCount)
	} else if sect := section.ToIPv6(); sect != nil {
		return sect.GetBlockCount(segmentCount)
	} else if sect := section.ToMAC(); sect != nil {
		return sect.GetBlockCount(segmentCount)
	}
	return section.addressDivisionGroupingBase.GetBlockCount(segmentCount)
}

// GetTrailingSection gets the subsection from the series starting from the given index.
// The first segment is at index 0.
func (section *AddressSection) GetTrailingSection(index int) *AddressSection {
	return section.getSubSection(index, section.GetSegmentCount())
}

// GetSubSection gets the subsection from the series starting from the given index and ending just before the give endIndex.
// The first segment is at index 0.
func (section *AddressSection) GetSubSection(index, endIndex int) *AddressSection {
	return section.getSubSection(index, endIndex)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *AddressSection) CopySubSegments(start, end int, segs []*AddressSegment) (count int) {
	return section.visitSubDivisions(start, end, func(index int, div *AddressDivision) bool { segs[index] = div.ToSegmentBase(); return false }, len(segs))
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *AddressSection) CopySegments(segs []*AddressSegment) (count int) {
	return section.visitDivisions(func(index int, div *AddressDivision) bool { segs[index] = div.ToSegmentBase(); return false }, len(segs))
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

func (section *AddressSection) IsPrefixed() bool {
	return section != nil && section.isPrefixed()
}

func (section *AddressSection) ToPrefixBlock() *AddressSection {
	return section.toPrefixBlock()
}

func (section *AddressSection) ToPrefixBlockLen(prefLen BitCount) *AddressSection {
	return section.toPrefixBlockLen(prefLen)
}

func (section *AddressSection) WithoutPrefixLen() *AddressSection {
	if !section.IsPrefixed() {
		return section
	}
	return section.withoutPrefixLen()
}

func (section *AddressSection) SetPrefixLen(prefixLen BitCount) *AddressSection {
	return section.setPrefixLen(prefixLen)
}

func (section *AddressSection) SetPrefixLenZeroed(prefixLen BitCount) (*AddressSection, addrerr.IncompatibleAddressError) {
	return section.setPrefixLenZeroed(prefixLen)
}

func (section *AddressSection) AdjustPrefixLen(prefixLen BitCount) *AddressSection {
	return section.adjustPrefixLen(prefixLen).ToSectionBase()
}

func (section *AddressSection) AdjustPrefixLenZeroed(prefixLen BitCount) (*AddressSection, addrerr.IncompatibleAddressError) {
	res, err := section.adjustPrefixLenZeroed(prefixLen)
	return res.ToSectionBase(), err
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

func (section *AddressSection) IsAdaptiveZero() bool {
	return section != nil && section.matchesZeroGrouping()
}

func (section *AddressSection) IsIP() bool {
	return section != nil && section.matchesIPSectionType()
}

func (section *AddressSection) IsIPv4() bool {
	return section != nil && section.matchesIPv4SectionType()
}

func (section *AddressSection) IsIPv6() bool {
	return section != nil && section.matchesIPv6SectionType()
}

func (section *AddressSection) IsMAC() bool {
	return section != nil && section.matchesMACSectionType()
}

func (section *AddressSection) ToDivGrouping() *AddressDivisionGrouping {
	return (*AddressDivisionGrouping)(unsafe.Pointer(section))
}

func (section *AddressSection) ToIP() *IPAddressSection {
	if section.IsIP() {
		return (*IPAddressSection)(unsafe.Pointer(section))
	}
	return nil
}

func (section *AddressSection) ToIPv6() *IPv6AddressSection {
	if section.IsIPv6() {
		return (*IPv6AddressSection)(unsafe.Pointer(section))
	}
	return nil
}

func (section *AddressSection) ToIPv4() *IPv4AddressSection {
	if section.IsIPv4() {
		return (*IPv4AddressSection)(unsafe.Pointer(section))
	}
	return nil
}

func (section *AddressSection) ToMAC() *MACAddressSection {
	if section.IsMAC() {
		return (*MACAddressSection)(unsafe.Pointer(section))
	}
	return nil
}

func (section *AddressSection) ToSectionBase() *AddressSection {
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

func (section *AddressSection) ReverseBits(perByte bool) (*AddressSection, addrerr.IncompatibleAddressError) {
	return section.reverseBits(perByte)
}

func (section *AddressSection) ReverseBytes() (*AddressSection, addrerr.IncompatibleAddressError) {
	return section.reverseBytes(false)
}

func (section *AddressSection) ReverseSegments() *AddressSection {
	if section.GetSegmentCount() <= 1 {
		if section.IsPrefixed() {
			return section.WithoutPrefixLen()
		}
		return section
	}
	res, _ := section.reverseSegments(
		func(i int) (*AddressSegment, addrerr.IncompatibleAddressError) {
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

func (section *AddressSection) ToHexString(with0xPrefix bool) (string, addrerr.IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toHexString(with0xPrefix)
}

func (section *AddressSection) ToOctalString(with0Prefix bool) (string, addrerr.IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toOctalString(with0Prefix)
}

func (section *AddressSection) ToBinaryString(with0bPrefix bool) (string, addrerr.IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toBinaryString(with0bPrefix)
}

func (section *AddressSection) ToCustomString(stringOptions addrstr.StringOptions) string {
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

func toSegments(
	bytes []byte,
	segmentCount int,
	bytesPerSegment int,
	bitsPerSegment BitCount,
	creator addressSegmentCreator,
	assignedPrefixLength PrefixLen) (segments []*AddressDivision, err addrerr.AddressValueError) {

	segments = createSegmentArray(segmentCount)
	byteIndex, segmentIndex := len(bytes), segmentCount-1
	for ; segmentIndex >= 0; segmentIndex-- {
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
		segmentPrefixLength := getSegmentPrefixLength(bitsPerSegment, assignedPrefixLength, segmentIndex)
		seg := creator.createSegment(value, value, segmentPrefixLength)
		segments[segmentIndex] = seg
	}
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
	return
}
