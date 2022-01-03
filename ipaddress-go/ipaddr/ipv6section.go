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
	"math/big"
	"math/bits"
	"sync/atomic"
	"unsafe"

	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrerr"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrstr"
)

func createIPv6Section(segments []*AddressDivision) *IPv6AddressSection {
	return &IPv6AddressSection{
		ipAddressSectionInternal{
			addressSectionInternal{
				addressDivisionGroupingInternal{
					addressDivisionGroupingBase: addressDivisionGroupingBase{
						divisions: standardDivArray{segments},
						addrType:  ipv6Type,
						cache: &valueCache{
							stringCache: stringCache{
								ipv6StringCache: &ipv6StringCache{},
								ipStringCache:   &ipStringCache{},
							},
						},
					},
				},
			},
		},
	}
}

func newIPv6Section(segments []*AddressDivision) *IPv6AddressSection {
	return createIPv6Section(segments)
}

func newIPv6SectionParsed(segments []*AddressDivision, isMultiple bool) (res *IPv6AddressSection) {
	res = createIPv6Section(segments)
	res.isMult = isMultiple
	return
}

func newIPv6SectionFromMixed(segments []*AddressDivision) (res *IPv6AddressSection) {
	res = createIPv6Section(segments)
	res.initMultiple()
	return
}

func newPrefixedIPv6SectionParsed(segments []*AddressDivision, isMultiple bool, prefixLength PrefixLen, singleOnly bool) (res *IPv6AddressSection) {
	res = createIPv6Section(segments)
	res.isMult = isMultiple
	if prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIP(), singleOnly, false, BitCount(len(segments)<<ipv6BitsToSegmentBitshift))
	}
	return
}

func NewIPv6Section(segments []*IPv6AddressSegment) *IPv6AddressSection {
	return createIPv6SectionFromSegs(segments, nil)
}

func NewIPv6PrefixedSection(segments []*IPv6AddressSegment, prefixLen PrefixLen) *IPv6AddressSection {
	return createIPv6SectionFromSegs(segments, prefixLen)
}

func createIPv6SectionFromSegs(orig []*IPv6AddressSegment, prefLen PrefixLen) (result *IPv6AddressSection) {
	divs, newPref, isMultiple := createDivisionsFromSegs(
		func(index int) *IPAddressSegment {
			return orig[index].ToIP()
		},
		len(orig),
		ipv6BitsToSegmentBitshift,
		IPv6BitsPerSegment,
		IPv6BytesPerSegment,
		IPv6MaxValuePerSegment,
		zeroIPv6Seg.ToIP(),
		zeroIPv6SegZeroPrefix.ToIP(),
		zeroIPv6SegPrefixBlock.ToIP(),
		prefLen)
	result = createIPv6Section(divs)
	result.prefixLength = newPref
	result.isMult = isMultiple
	return result
}

// NewIPv6SectionFromBigInt creates an IPv6 section from the given big integer, returning an error if the value is too large for the given number of segments.
func NewIPv6SectionFromBigInt(val *big.Int, segmentCount int) (res *IPv6AddressSection, err addrerr.AddressValueError) {
	if val.Sign() < 0 {
		err = &addressValueError{
			addressError: addressError{key: "ipaddress.error.negative"},
		}
		return
	}
	return newIPv6SectionFromWords(val.Bits(), segmentCount, nil, false)
}

func NewIPv6SectionFromPrefixedBigInt(val *big.Int, segmentCount int, prefixLen PrefixLen) (res *IPv6AddressSection, err addrerr.AddressValueError) {
	if val.Sign() < 0 {
		err = &addressValueError{
			addressError: addressError{key: "ipaddress.error.negative"},
		}
		return
	}
	return newIPv6SectionFromWords(val.Bits(), segmentCount, prefixLen, false)
}

func NewIPv6SectionFromBytes(bytes []byte) (res *IPv6AddressSection, err addrerr.AddressValueError) {
	return newIPv6SectionFromBytes(bytes, len(bytes)>>1, nil, false)
}

// NewIPv6SectionFromSegmentedBytes allows you to specify the segment count from the supplied bytes.
// It is useful if the byte array has leading zeros.
func NewIPv6SectionFromSegmentedBytes(bytes []byte, segmentCount int) (res *IPv6AddressSection, err addrerr.AddressValueError) {
	return newIPv6SectionFromBytes(bytes, segmentCount, nil, false)
}

func NewIPv6SectionFromPrefixedBytes(bytes []byte, segmentCount int, prefixLength PrefixLen) (res *IPv6AddressSection, err addrerr.AddressValueError) {
	return newIPv6SectionFromBytes(bytes, segmentCount, prefixLength, false)
}

func newIPv6SectionFromBytes(bytes []byte, segmentCount int, prefixLength PrefixLen, singleOnly bool) (res *IPv6AddressSection, err addrerr.AddressValueError) {
	if segmentCount < 0 {
		segmentCount = len(bytes) >> 1
	}
	expectedByteCount := segmentCount << 1
	segments, err := toSegments(
		bytes,
		segmentCount,
		IPv6BytesPerSegment,
		IPv6BitsPerSegment,
		IPv6Network.getIPAddressCreator(),
		prefixLength)
	if err == nil {
		res = createIPv6Section(segments)
		if prefixLength != nil {
			assignPrefix(prefixLength, segments, res.ToIP(), singleOnly, false, BitCount(segmentCount<<ipv6BitsToSegmentBitshift))
		}
		if expectedByteCount == len(bytes) && len(bytes) > 0 {
			bytes = cloneBytes(bytes)
			res.cache.bytesCache = &bytesCache{lowerBytes: bytes}
			if !res.isMult { // not a prefix block
				res.cache.bytesCache.upperBytes = bytes
			}
		}
	}
	return
}

func newIPv6SectionFromWords(words []big.Word, segmentCount int, prefixLength PrefixLen, singleOnly bool) (res *IPv6AddressSection, err addrerr.AddressValueError) {
	if segmentCount < 0 {
		wordBitSize := bits.UintSize
		segmentCount = (len(words) * wordBitSize) >> 4
	}
	segments, err := toSegmentsFromWords(
		words,
		segmentCount,
		prefixLength)
	if err == nil {
		res = createIPv6Section(segments)
		if prefixLength != nil {
			assignPrefix(prefixLength, segments, res.ToIP(), singleOnly, false, BitCount(segmentCount<<ipv6BitsToSegmentBitshift))
		}
	}
	return
}

func toSegmentsFromWords(
	words []big.Word,
	segmentCount int,
	prefixLength PrefixLen) (segments []*AddressDivision, err addrerr.AddressValueError) {

	wordLen := len(words)
	wordBitSize := bits.UintSize
	segmentsPerWord := wordBitSize >> ipv6BitsToSegmentBitshift
	segments = createSegmentArray(segmentCount)
	var currentWord big.Word
	if wordLen > 0 {
		currentWord = words[0]
	}
	// start with little end
	for wordIndex, wordSegmentIndex, segmentIndex := 0, 0, segmentCount-1; ; segmentIndex-- {
		var value IPv6SegInt
		if wordIndex < wordLen {
			value = IPv6SegInt(currentWord)
			currentWord >>= uint(IPv6BitsPerSegment)
			wordSegmentIndex++
		}
		segmentPrefixLength := getSegmentPrefixLength(IPv6BitsPerSegment, prefixLength, segmentIndex)
		seg := NewIPv6PrefixedSegment(value, segmentPrefixLength)
		segments[segmentIndex] = seg.ToDiv()
		if wordSegmentIndex == segmentsPerWord {
			wordSegmentIndex = 0
			wordIndex++
			if wordIndex < wordLen {
				currentWord = words[wordIndex]
			}
		}
		if segmentIndex == 0 {
			// any remaining words should be zero
			var isErr bool
			if isErr = currentWord != 0; !isErr {
				for wordIndex++; wordIndex < wordLen; wordIndex++ {
					if isErr = words[wordIndex] != 0; isErr {
						break
					}
				}
			}
			if isErr {
				err = &addressValueError{
					addressError: addressError{key: "ipaddress.error.exceeds.size"},
					val:          int(words[wordIndex]),
				}
			}
			break
		}
	}
	return
}

func NewIPv6SectionFromUint64(highBytes, lowBytes uint64, segmentCount int) (res *IPv6AddressSection) {
	return NewIPv6SectionFromPrefixedUint64(highBytes, lowBytes, segmentCount, nil)
}

func NewIPv6SectionFromPrefixedUint64(highBytes, lowBytes uint64, segmentCount int, prefixLength PrefixLen) (res *IPv6AddressSection) {
	if segmentCount < 0 {
		segmentCount = IPv6SegmentCount
	}
	segments := createSegmentsUint64(
		segmentCount,
		highBytes,
		lowBytes,
		IPv6BytesPerSegment,
		IPv6BitsPerSegment,
		IPv6Network.getIPAddressCreator(),
		prefixLength)
	res = createIPv6Section(segments)
	if prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIP(), false, false, BitCount(segmentCount<<ipv6BitsToSegmentBitshift))
	}
	return
}

func NewIPv6SectionFromVals(vals IPv6SegmentValueProvider, segmentCount int) (res *IPv6AddressSection) {
	res = NewIPv6SectionFromPrefixedRangeVals(vals, nil, segmentCount, nil)
	return
}

func NewIPv6SectionFromPrefixedVals(vals IPv6SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv6AddressSection) {
	return NewIPv6SectionFromPrefixedRangeVals(vals, nil, segmentCount, prefixLength)
}

func NewIPv6SectionFromRangeVals(vals, upperVals IPv6SegmentValueProvider, segmentCount int) (res *IPv6AddressSection) {
	res = NewIPv6SectionFromPrefixedRangeVals(vals, upperVals, segmentCount, nil)
	return
}

func NewIPv6SectionFromPrefixedRangeVals(vals, upperVals IPv6SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv6AddressSection) {
	if segmentCount < 0 {
		segmentCount = 0
	}
	segments, isMultiple := createSegments(
		WrappedIPv6SegmentValueProvider(vals),
		WrappedIPv6SegmentValueProvider(upperVals),
		segmentCount,
		IPv6BitsPerSegment,
		IPv6Network.getIPAddressCreator(),
		prefixLength)
	res = createIPv6Section(segments)
	res.isMult = isMultiple
	if prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIP(), false, false, BitCount(segmentCount<<ipv6BitsToSegmentBitshift))
	}
	return
}

func NewIPv6SectionFromMAC(eui *MACAddress) (res *IPv6AddressSection, err addrerr.IncompatibleAddressError) {
	segments := createSegmentArray(4)
	if err = toIPv6SegmentsFromEUI(segments, 0, eui.GetSection(), nil); err != nil {
		return
	}
	res = createIPv6Section(segments)
	res.isMult = eui.isMultiple()
	return
}

// IPv6AddressSection represents a section of an IPv6 address comprising 0 to 8 IPv6 address segments.
// The zero values is a section with zero segments.
type IPv6AddressSection struct {
	ipAddressSectionInternal
}

func (section *IPv6AddressSection) Contains(other AddressSectionType) bool {
	if section == nil {
		return other == nil || other.ToSectionBase() == nil
	}
	return section.contains(other)
}

func (section *IPv6AddressSection) Equal(other AddressSectionType) bool {
	if section == nil {
		return other == nil || other.ToSectionBase() == nil
	}
	return section.equal(other)
}

func (section *IPv6AddressSection) Compare(item AddressItem) int {
	return CountComparator.Compare(section, item)
}

func (section *IPv6AddressSection) CompareSize(other StandardDivGroupingType) int {
	if section == nil {
		if other != nil && other.ToDivGrouping() != nil {
			// we have size 0, other has size >= 1
			return -1
		}
		return 0
	}
	return section.compareSize(other)
}

func (section *IPv6AddressSection) GetIPVersion() IPVersion {
	return IPv6
}

func (section *IPv6AddressSection) GetBitsPerSegment() BitCount {
	return IPv6BitsPerSegment
}

func (section *IPv6AddressSection) GetBytesPerSegment() int {
	return IPv6BytesPerSegment
}

func (section *IPv6AddressSection) GetCount() *big.Int {
	if section == nil {
		return bigZero()
	}
	return section.cacheCount(func() *big.Int {
		return count(func(index int) uint64 {
			return section.GetSegment(index).GetValueCount()
		}, section.GetSegmentCount(), 2, 0x7fffffffffff)
	})
}

func (section *IPv6AddressSection) IsMultiple() bool {
	return section != nil && section.isMultiple()
}

func (section *IPv6AddressSection) IsPrefixed() bool {
	return section != nil && section.isPrefixed()
}

func (section *IPv6AddressSection) GetBlockCount(segmentCount int) *big.Int {
	return section.calcCount(func() *big.Int {
		return count(func(index int) uint64 {
			return section.GetSegment(index).GetValueCount()
		}, segmentCount, 2, 0x7fffffffffff)
	})
}

func (section *IPv6AddressSection) GetPrefixCount() *big.Int {
	return section.cachePrefixCount(func() *big.Int {
		return section.GetPrefixCountLen(section.getPrefixLen().bitCount())
	})
}

func (section *IPv6AddressSection) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	if prefixLen <= 0 {
		return bigOne()
	} else if bc := section.GetBitCount(); prefixLen >= bc {
		return section.GetCount()
	}
	networkSegmentIndex := getNetworkSegmentIndex(prefixLen, section.GetBytesPerSegment(), section.GetBitsPerSegment())
	hostSegmentIndex := getHostSegmentIndex(prefixLen, section.GetBytesPerSegment(), section.GetBitsPerSegment())
	return section.calcCount(func() *big.Int {
		return count(func(index int) uint64 {
			if (networkSegmentIndex == hostSegmentIndex) && index == networkSegmentIndex {
				return section.GetSegment(index).GetPrefixValueCount()
			}
			return section.GetSegment(index).GetValueCount()
		},
			networkSegmentIndex+1,
			2,
			0x7fffffffffff)
	})
}

func (section *IPv6AddressSection) GetSegment(index int) *IPv6AddressSegment {
	return section.getDivision(index).ToIPv6()
}

// GetTrailingSection gets the subsection from the series starting from the given index.
// The first segment is at index 0.
func (section *IPv6AddressSection) GetTrailingSection(index int) *IPv6AddressSection {
	return section.GetSubSection(index, section.GetSegmentCount())
}

// GetSubSection gets the subsection from the series starting from the given index and ending just before the give endIndex.
// The first segment is at index 0.
func (section *IPv6AddressSection) GetSubSection(index, endIndex int) *IPv6AddressSection {
	return section.getSubSection(index, endIndex).ToIPv6()
}

func (section *IPv6AddressSection) GetNetworkSection() *IPv6AddressSection {
	return section.getNetworkSection().ToIPv6()
}

func (section *IPv6AddressSection) GetNetworkSectionLen(prefLen BitCount) *IPv6AddressSection {
	return section.getNetworkSectionLen(prefLen).ToIPv6()
}

func (section *IPv6AddressSection) GetHostSection() *IPv6AddressSection {
	return section.getHostSection().ToIPv6()
}

func (section *IPv6AddressSection) GetHostSectionLen(prefLen BitCount) *IPv6AddressSection {
	return section.getHostSectionLen(prefLen).ToIPv6()
}

func (section *IPv6AddressSection) GetNetworkMask() *IPv6AddressSection {
	return section.getNetworkMask(IPv6Network).ToIPv6()
}

func (section *IPv6AddressSection) GetHostMask() *IPv6AddressSection {
	return section.getHostMask(IPv6Network).ToIPv6()
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *IPv6AddressSection) CopySubSegments(start, end int, segs []*IPv6AddressSegment) (count int) {
	return section.visitSubDivisions(start, end, func(index int, div *AddressDivision) bool { segs[index] = div.ToIPv6(); return false }, len(segs))
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *IPv6AddressSection) CopySegments(segs []*IPv6AddressSegment) (count int) {
	return section.visitDivisions(func(index int, div *AddressDivision) bool { segs[index] = div.ToIPv6(); return false }, len(segs))
}

// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this section.
func (section *IPv6AddressSection) GetSegments() (res []*IPv6AddressSegment) {
	res = make([]*IPv6AddressSegment, section.GetSegmentCount())
	section.CopySegments(res)
	return
}

func (section *IPv6AddressSection) Mask(other *IPv6AddressSection) (res *IPv6AddressSection, err addrerr.IncompatibleAddressError) {
	return section.maskPrefixed(other, true)
}

func (section *IPv6AddressSection) maskPrefixed(other *IPv6AddressSection, retainPrefix bool) (res *IPv6AddressSection, err addrerr.IncompatibleAddressError) {
	sec, err := section.mask(other.ToIP(), retainPrefix)
	if err == nil {
		res = sec.ToIPv6()
	}
	return
}

func (section *IPv6AddressSection) BitwiseOr(other *IPv6AddressSection) (res *IPv6AddressSection, err addrerr.IncompatibleAddressError) {
	return section.bitwiseOrPrefixed(other, true)
}

func (section *IPv6AddressSection) bitwiseOrPrefixed(other *IPv6AddressSection, retainPrefix bool) (res *IPv6AddressSection, err addrerr.IncompatibleAddressError) {
	sec, err := section.bitwiseOr(other.ToIP(), retainPrefix)
	if err == nil {
		res = sec.ToIPv6()
	}
	return
}

func (section *IPv6AddressSection) MatchesWithMask(other *IPv6AddressSection, mask *IPv6AddressSection) bool {
	return section.matchesWithMask(other.ToIP(), mask.ToIP())
}

func (section *IPv6AddressSection) Subtract(other *IPv6AddressSection) (res []*IPv6AddressSection, err addrerr.SizeMismatchError) {
	sections, err := section.subtract(other.ToIP())
	if err == nil {
		res = cloneIPSectsToIPv6Sects(sections)
	}
	return
}

func (section *IPv6AddressSection) Intersect(other *IPv6AddressSection) (res *IPv6AddressSection, err addrerr.SizeMismatchError) {
	sec, err := section.intersect(other.ToIP())
	if err == nil {
		res = sec.ToIPv6()
	}
	return
}

func (section *IPv6AddressSection) GetLower() *IPv6AddressSection {
	return section.getLower().ToIPv6()
}

func (section *IPv6AddressSection) GetUpper() *IPv6AddressSection {
	return section.getUpper().ToIPv6()
}

func (section *IPv6AddressSection) ToZeroHost() (*IPv6AddressSection, addrerr.IncompatibleAddressError) {
	res, err := section.toZeroHost(false)
	return res.ToIPv6(), err
}

func (section *IPv6AddressSection) ToZeroHostLen(prefixLength BitCount) (*IPv6AddressSection, addrerr.IncompatibleAddressError) {
	res, err := section.toZeroHostLen(prefixLength)
	return res.ToIPv6(), err
}

func (section *IPv6AddressSection) ToZeroNetwork() *IPv6AddressSection {
	return section.toZeroNetwork().ToIPv6()
}

func (section *IPv6AddressSection) ToMaxHost() (*IPv6AddressSection, addrerr.IncompatibleAddressError) {
	res, err := section.toMaxHost()
	return res.ToIPv6(), err
}

func (section *IPv6AddressSection) ToMaxHostLen(prefixLength BitCount) (*IPv6AddressSection, addrerr.IncompatibleAddressError) {
	res, err := section.toMaxHostLen(prefixLength)
	return res.ToIPv6(), err
}

func (section *IPv6AddressSection) ToPrefixBlock() *IPv6AddressSection {
	return section.toPrefixBlock().ToIPv6()
}

func (section *IPv6AddressSection) ToPrefixBlockLen(prefLen BitCount) *IPv6AddressSection {
	return section.toPrefixBlockLen(prefLen).ToIPv6()
}

func (section *IPv6AddressSection) ToBlock(segmentIndex int, lower, upper SegInt) *IPv6AddressSection {
	return section.toBlock(segmentIndex, lower, upper).ToIPv6()
}

func (section *IPv6AddressSection) WithoutPrefixLen() *IPv6AddressSection {
	if !section.IsPrefixed() {
		return section
	}
	return section.withoutPrefixLen().ToIPv6()
}

func (section *IPv6AddressSection) SetPrefixLen(prefixLen BitCount) *IPv6AddressSection {
	return section.setPrefixLen(prefixLen).ToIPv6()
}

func (section *IPv6AddressSection) SetPrefixLenZeroed(prefixLen BitCount) (*IPv6AddressSection, addrerr.IncompatibleAddressError) {
	res, err := section.setPrefixLenZeroed(prefixLen)
	return res.ToIPv6(), err
}

func (section *IPv6AddressSection) AdjustPrefixLen(prefixLen BitCount) *IPv6AddressSection {
	return section.adjustPrefixLen(prefixLen).ToIPv6()
}

func (section *IPv6AddressSection) AdjustPrefixLenZeroed(prefixLen BitCount) (*IPv6AddressSection, addrerr.IncompatibleAddressError) {
	res, err := section.adjustPrefixLenZeroed(prefixLen)
	return res.ToIPv6(), err
}

func (section *IPv6AddressSection) AssignPrefixForSingleBlock() *IPv6AddressSection {
	return section.assignPrefixForSingleBlock().ToIPv6()
}

func (section *IPv6AddressSection) AssignMinPrefixForBlock() *IPv6AddressSection {
	return section.assignMinPrefixForBlock().ToIPv6()
}

func (section *IPv6AddressSection) Iterator() IPv6SectionIterator {
	if section == nil {
		return ipv6SectionIterator{nilSectIterator()}
	}
	return ipv6SectionIterator{section.sectionIterator(nil)}
}

func (section *IPv6AddressSection) PrefixIterator() IPv6SectionIterator {
	return ipv6SectionIterator{section.prefixIterator(false)}
}

func (section *IPv6AddressSection) PrefixBlockIterator() IPv6SectionIterator {
	return ipv6SectionIterator{section.prefixIterator(true)}
}

func (section *IPv6AddressSection) BlockIterator(segmentCount int) IPv6SectionIterator {
	return ipv6SectionIterator{section.blockIterator(segmentCount)}
}

func (section *IPv6AddressSection) SequentialBlockIterator() IPv6SectionIterator {
	return ipv6SectionIterator{section.sequentialBlockIterator()}
}

func (section *IPv6AddressSection) GetZeroSegments() RangeList {
	vals := section.getZeroVals()
	if vals == nil {
		return RangeList{}
	}
	return vals.zeroSegments
}

func (section *IPv6AddressSection) GetZeroRangeSegments() RangeList {
	vals := section.getZeroVals()
	if vals == nil {
		return RangeList{}
	}
	return vals.zeroRangeSegments
}

func (section *IPv6AddressSection) getZeroVals() *zeroRangeCache {
	cache := section.cache
	if cache == nil {
		return section.calcZeroVals()
	}
	zeroVals := cache.zeroVals
	if zeroVals == nil {
		zeroVals = section.calcZeroVals()
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.zeroVals))
		atomic.StorePointer(dataLoc, unsafe.Pointer(zeroVals))
	}
	return zeroVals
}

func (section *IPv6AddressSection) calcZeroVals() *zeroRangeCache {
	zeroSegs := section.getZeroSegments(false)
	var zeroRangeSegs RangeList
	if section.IsPrefixed() {
		zeroRangeSegs = section.getZeroSegments(true)
	} else {
		zeroRangeSegs = zeroSegs
	}
	return &zeroRangeCache{zeroSegs, zeroRangeSegs}
}

// GetCompressIndexAndCount chooses a single segment to be compressed in an IPv6 string. If no segment could be chosen then count is 0.
// If options is nil, no segment will be chosen.  If createMixed is true, will assume the address string will be mixed IPv6/v4.
func (section *IPv6AddressSection) getCompressIndexAndCount(options addrstr.CompressOptions, createMixed bool) (maxIndex, maxCount int) {
	if options != nil {
		rangeSelection := options.GetCompressionChoiceOptions()
		var compressibleSegs RangeList
		if rangeSelection.CompressHost() {
			compressibleSegs = section.GetZeroRangeSegments()
		} else {
			compressibleSegs = section.GetZeroSegments()
		}
		maxCount = 0
		segmentCount := section.GetSegmentCount()
		//compressMixed := createMixed && options.GetMixedCompressionOptions().compressMixed(section)
		compressMixed := createMixed && compressMixedSect(options.GetMixedCompressionOptions(), section)
		preferHost := rangeSelection == addrstr.HostPreferred
		preferMixed := createMixed && (rangeSelection == addrstr.MixedPreferred)
		for i := compressibleSegs.size() - 1; i >= 0; i-- {
			rng := compressibleSegs.getRange(i)
			index := rng.index
			count := rng.length
			if createMixed {
				//so here we shorten the range to exclude the mixed part if necessary
				mixedIndex := IPv6MixedOriginalSegmentCount
				if !compressMixed ||
					index > mixedIndex || index+count < segmentCount { //range does not include entire mixed part.  We never compress only part of a mixed part.
					//the compressible range must stop at the mixed part
					if val := mixedIndex - index; val < count {
						count = val
					}
				}
			}
			//select this range if is the longest
			if count > 0 && count >= maxCount && (options.CompressSingle() || count > 1) {
				maxIndex = index
				maxCount = count
			}
			if preferHost && section.IsPrefixed() &&
				(BitCount(index+count)*section.GetBitsPerSegment()) > section.getNetworkPrefixLen().bitCount() { //this range contains the host
				//Since we are going backwards, this means we select as the maximum any zero segment that includes the host
				break
			}
			if preferMixed && index+count >= segmentCount { //this range contains the mixed section
				//Since we are going backwards, this means we select to compress the mixed segment
				break
			}
		}
	}
	return
}

func compressMixedSect(m addrstr.MixedCompressionOptions, addressSection *IPv6AddressSection) bool {
	switch m {
	case addrstr.AllowMixedCompression:
		return true
	case addrstr.NoMixedCompression:
		return false
	case addrstr.MixedCompressionNoHost:
		return !addressSection.IsPrefixed()
	case addrstr.MixedCompressionCoveredByHost:
		if addressSection.IsPrefixed() {
			mixedDistance := IPv6MixedOriginalSegmentCount
			mixedCount := addressSection.GetSegmentCount() - mixedDistance
			if mixedCount > 0 {
				return (BitCount(mixedDistance) * addressSection.GetBitsPerSegment()) >= addressSection.getNetworkPrefixLen().bitCount()
			}
		}
		return true
	default:
		return true
	}
}

func (section *IPv6AddressSection) getZeroSegments(includeRanges bool) RangeList {
	divisionCount := section.GetSegmentCount()
	isFullRangeHost := section.IsPrefixBlock()
	includeRanges = includeRanges && isFullRangeHost
	var currentIndex, currentCount, rangeCount int
	var ranges [IPv6SegmentCount >> 1]Range
	for i := 0; i < divisionCount; i++ {
		division := section.GetSegment(i)
		isCompressible := division.IsZero() ||
			(includeRanges && division.IsPrefixed() && division.isSinglePrefixBlock(0, division.getUpperDivisionValue(), division.getDivisionPrefixLength().bitCount()))
		if isCompressible {
			currentCount++
			if currentCount == 1 {
				currentIndex = i
			}
			if i == divisionCount-1 {
				ranges[rangeCount] = Range{index: currentIndex, length: currentCount}
				rangeCount++
			}
		} else if currentCount > 0 {
			ranges[rangeCount] = Range{index: currentIndex, length: currentCount}
			rangeCount++
			currentCount = 0
		}
	}
	if rangeCount == 0 {
		return RangeList{}
	}
	return RangeList{ranges[:rangeCount]}
}

func (section *IPv6AddressSection) IncrementBoundary(increment int64) *IPv6AddressSection {
	return section.incrementBoundary(increment).ToIPv6()
}

func getIPv6MaxValue(segmentCount int) *big.Int {
	return new(big.Int).Set(ipv6MaxValues[segmentCount])
}

var ipv6MaxValues = []*big.Int{
	bigZero(),
	new(big.Int).SetUint64(IPv6MaxValuePerSegment),
	new(big.Int).SetUint64(0xffffffff),
	new(big.Int).SetUint64(0xffffffffffff),
	maxInt(4),
	maxInt(5),
	maxInt(6),
	maxInt(7),
	maxInt(8),
}

func maxInt(segCount int) *big.Int {
	res := new(big.Int).SetUint64(1)
	return res.Lsh(res, 16*uint(segCount)).Sub(res, bigOneConst())
}

func (section *IPv6AddressSection) Increment(increment int64) *IPv6AddressSection {
	if increment == 0 && !section.isMultiple() {
		return section
	}
	lowerValue := section.GetValue()
	upperValue := section.GetUpperValue()
	count := section.GetCount()
	var bigIncrement big.Int
	bigIncrement.SetInt64(increment)
	isOverflow := checkOverflowBig(increment, &bigIncrement, lowerValue, upperValue, count, func() *big.Int { return getIPv6MaxValue(section.GetSegmentCount()) })
	if isOverflow {
		return nil
	}
	prefixLength := section.getPrefixLen()
	result := fastIncrement(
		section.ToSectionBase(),
		increment,
		IPv6Network.getIPAddressCreator(),
		section.getLower,
		section.getUpper,
		prefixLength)
	if result != nil {
		return result.ToIPv6()
	}
	bigIncrement.SetInt64(increment)
	return incrementBig(
		section.ToSectionBase(),
		increment,
		&bigIncrement,
		IPv6Network.getIPAddressCreator(),
		section.getLower,
		section.getUpper,
		prefixLength).ToIPv6()
}

func (section *IPv6AddressSection) SpanWithPrefixBlocks() []*IPv6AddressSection {
	if section.IsSequential() {
		if section.IsSinglePrefixBlock() {
			return []*IPv6AddressSection{section}
		}
		wrapped := WrapIPSection(section.ToIP())
		spanning := getSpanningPrefixBlocks(wrapped, wrapped)
		return cloneToIPv6Sections(spanning)
	}
	wrapped := WrapIPSection(section.ToIP())
	return cloneToIPv6Sections(spanWithPrefixBlocks(wrapped))
}

func (section *IPv6AddressSection) SpanWithPrefixBlocksTo(other *IPv6AddressSection) ([]*IPv6AddressSection, addrerr.SizeMismatchError) {
	if err := section.checkSectionCount(other.ToIP()); err != nil {
		return nil, err
	}
	return cloneToIPv6Sections(
		getSpanningPrefixBlocks(
			WrapIPSection(section.ToIP()),
			WrapIPSection(other.ToIP()),
		),
	), nil
}

func (section *IPv6AddressSection) SpanWithSequentialBlocks() []*IPv6AddressSection {
	if section.IsSequential() {
		return []*IPv6AddressSection{section}
	}
	wrapped := WrapIPSection(section.ToIP())
	return cloneToIPv6Sections(spanWithSequentialBlocks(wrapped))
}

func (section *IPv6AddressSection) SpanWithSequentialBlocksTo(other *IPv6AddressSection) ([]*IPv6AddressSection, addrerr.SizeMismatchError) {
	if err := section.checkSectionCount(other.ToIP()); err != nil {
		return nil, err
	}
	return cloneToIPv6Sections(
		getSpanningSequentialBlocks(
			WrapIPSection(section.ToIP()),
			WrapIPSection(other.ToIP()),
		),
	), nil
}

func (section *IPv6AddressSection) CoverWithPrefixBlockTo(other *IPv6AddressSection) (*IPv6AddressSection, addrerr.SizeMismatchError) {
	res, err := section.coverWithPrefixBlockTo(other.ToIP())
	return res.ToIPv6(), err
}

func (section *IPv6AddressSection) CoverWithPrefixBlock() *IPv6AddressSection {
	return section.coverWithPrefixBlock().ToIPv6()
}

func (section *IPv6AddressSection) checkSectionCounts(sections []*IPv6AddressSection) addrerr.SizeMismatchError {
	segCount := section.GetSegmentCount()
	length := len(sections)
	for i := 0; i < length; i++ {
		section2 := sections[i]
		if section2 == nil {
			continue
		}
		if section2.GetSegmentCount() != segCount {
			return &sizeMismatchError{incompatibleAddressError{addressError{key: "ipaddress.error.sizeMismatch"}}}
		}
	}
	return nil
}

//
// MergeToSequentialBlocks merges this with the list of sections to produce the smallest array of blocks that are sequential
//
// The resulting array is sorted from lowest address value to highest, regardless of the size of each prefix block.
func (section *IPv6AddressSection) MergeToSequentialBlocks(sections ...*IPv6AddressSection) ([]*IPv6AddressSection, addrerr.SizeMismatchError) {
	if err := section.checkSectionCounts(sections); err != nil {
		return nil, err
	}
	series := cloneIPv6Sections(section, sections)
	blocks := getMergedSequentialBlocks(series)
	return cloneToIPv6Sections(blocks), nil
}

//
// MergeToPrefixBlocks merges this with the list of sections to produce the smallest array of prefix blocks.
//
// The resulting array is sorted from lowest address value to highest, regardless of the size of each prefix block.
func (section *IPv6AddressSection) MergeToPrefixBlocks(sections ...*IPv6AddressSection) ([]*IPv6AddressSection, addrerr.SizeMismatchError) {
	if err := section.checkSectionCounts(sections); err != nil {
		return nil, err
	}
	series := cloneIPv6Sections(section, sections)
	blocks := getMergedPrefixBlocks(series)
	return cloneToIPv6Sections(blocks), nil
}

func (section *IPv6AddressSection) ReverseBits(perByte bool) (*IPv6AddressSection, addrerr.IncompatibleAddressError) {
	res, err := section.reverseBits(perByte)
	return res.ToIPv6(), err
}

func (section *IPv6AddressSection) ReverseBytes() (*IPv6AddressSection, addrerr.IncompatibleAddressError) {
	res, err := section.reverseBytes(false)
	return res.ToIPv6(), err
}

func (section *IPv6AddressSection) ReverseSegments() *IPv6AddressSection {
	if section.GetSegmentCount() <= 1 {
		if section.IsPrefixed() {
			return section.WithoutPrefixLen()
		}
		return section
	}
	res, _ := section.reverseSegments(
		func(i int) (*AddressSegment, addrerr.IncompatibleAddressError) {
			return section.GetSegment(i).WithoutPrefixLen().ToSegmentBase(), nil
		},
	)
	return res.ToIPv6()
}

func (section *IPv6AddressSection) Append(other *IPv6AddressSection) *IPv6AddressSection {
	count := section.GetSegmentCount()
	return section.ReplaceLen(count, count, other, 0, other.GetSegmentCount())
}

func (section *IPv6AddressSection) Insert(index int, other *IPv6AddressSection) *IPv6AddressSection {
	return section.insert(index, other.ToIP(), ipv6BitsToSegmentBitshift).ToIPv6()
}

// Replace replaces the segments of this section starting at the given index with the given replacement segments
func (section *IPv6AddressSection) Replace(index int, replacement *IPv6AddressSection) *IPv6AddressSection {
	return section.ReplaceLen(index, index+replacement.GetSegmentCount(), replacement, 0, replacement.GetSegmentCount())
}

// ReplaceLen replaces the segments starting from startIndex and ending before endIndex with the segments starting at replacementStartIndex and
//ending before replacementEndIndex from the replacement section
func (section *IPv6AddressSection) ReplaceLen(startIndex, endIndex int, replacement *IPv6AddressSection, replacementStartIndex, replacementEndIndex int) *IPv6AddressSection {
	return section.replaceLen(startIndex, endIndex, replacement.ToIP(), replacementStartIndex, replacementEndIndex, ipv6BitsToSegmentBitshift).ToIPv6()
}

func (section *IPv6AddressSection) IsAdaptiveZero() bool {
	return section != nil && section.matchesZeroGrouping()
}

var (
	compressAll            = new(addrstr.CompressOptionsBuilder).SetCompressSingle(true).SetRangeSelection(addrstr.ZerosOrHost).ToOptions()
	compressMixed          = new(addrstr.CompressOptionsBuilder).SetCompressSingle(true).SetRangeSelection(addrstr.MixedPreferred).ToOptions()
	compressAllNoSingles   = new(addrstr.CompressOptionsBuilder).SetRangeSelection(addrstr.ZerosOrHost).ToOptions()
	compressHostPreferred  = new(addrstr.CompressOptionsBuilder).SetCompressSingle(true).SetRangeSelection(addrstr.HostPreferred).ToOptions()
	compressZeros          = new(addrstr.CompressOptionsBuilder).SetCompressSingle(true).SetRangeSelection(addrstr.ZerosCompression).ToOptions()
	compressZerosNoSingles = new(addrstr.CompressOptionsBuilder).SetRangeSelection(addrstr.ZerosCompression).ToOptions()

	uncWildcards = new(addrstr.WildcardOptionsBuilder).SetWildcardOptions(addrstr.WildcardsNetworkOnly).SetWildcards(
		new(addrstr.WildcardsBuilder).SetRangeSeparator(IPv6UncRangeSeparatorStr).SetWildcard(SegmentWildcardStr).ToWildcards()).ToOptions()
	base85Wildcards = new(addrstr.WildcardsBuilder).SetRangeSeparator(AlternativeRangeSeparatorStr).ToWildcards()

	mixedParams         = new(addrstr.IPv6StringOptionsBuilder).SetMixed(true).SetCompressOptions(compressMixed).ToOptions()
	ipv6FullParams      = new(addrstr.IPv6StringOptionsBuilder).SetExpandedSegments(true).SetWildcardOptions(wildcardsRangeOnlyNetworkOnly).ToOptions()
	ipv6CanonicalParams = new(addrstr.IPv6StringOptionsBuilder).SetCompressOptions(compressAllNoSingles).ToOptions()
	//uncParams           = new(addrstr.IPv6StringOptionsBuilder).SetSeparator(IPv6UncSegmentSeparator).SetZoneSeparator(IPv6UncZoneSeparator).
	//			SetAddressSuffix(IPv6UncSuffix).SetWildcardOptions(uncWildcards).ToOptions()
	ipv6CompressedParams         = new(addrstr.IPv6StringOptionsBuilder).SetCompressOptions(compressAll).ToOptions()
	ipv6normalizedParams         = new(addrstr.IPv6StringOptionsBuilder).ToOptions()
	canonicalWildcardParams      = new(addrstr.IPv6StringOptionsBuilder).SetWildcardOptions(allWildcards).SetCompressOptions(compressZerosNoSingles).ToOptions()
	ipv6NormalizedWildcardParams = new(addrstr.IPv6StringOptionsBuilder).SetWildcardOptions(allWildcards).ToOptions()    //no compression
	ipv6SqlWildcardParams        = new(addrstr.IPv6StringOptionsBuilder).SetWildcardOptions(allSQLWildcards).ToOptions() //no compression
	wildcardCompressedParams     = new(addrstr.IPv6StringOptionsBuilder).SetWildcardOptions(allWildcards).SetCompressOptions(compressZeros).ToOptions()
	networkPrefixLengthParams    = new(addrstr.IPv6StringOptionsBuilder).SetCompressOptions(compressHostPreferred).ToOptions()

	ipv6ReverseDNSParams = new(addrstr.IPv6StringOptionsBuilder).SetReverse(true).SetAddressSuffix(IPv6ReverseDnsSuffix).
				SetSplitDigits(true).SetExpandedSegments(true).SetSeparator('.').ToOptions()
	//base85Params = new(addrstr.IPStringOptionsBuilder).SetRadix(85).SetExpandedSegments(true).
	//		SetWildcards(base85Wildcards).SetZoneSeparator(IPv6AlternativeZoneSeparator).ToOptions()
	ipv6SegmentedBinaryParams = new(addrstr.IPStringOptionsBuilder).SetRadix(2).SetSeparator(IPv6SegmentSeparator).SetSegmentStrPrefix(BinaryPrefix).
					SetExpandedSegments(true).ToOptions()
)

func (section *IPv6AddressSection) String() string {
	if section == nil {
		return nilString()
	}
	return section.toString()
}

func (section *IPv6AddressSection) ToHexString(with0xPrefix bool) (string, addrerr.IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toHexString(with0xPrefix)
}

func (section *IPv6AddressSection) ToOctalString(with0Prefix bool) (string, addrerr.IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toOctalString(with0Prefix)
}

func (section *IPv6AddressSection) ToBinaryString(with0bPrefix bool) (string, addrerr.IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toBinaryString(with0bPrefix)
}

// ToCanonicalString produces a canonical string.
//
//If this section has a prefix length, it will be included in the string.
func (section *IPv6AddressSection) ToCanonicalString() string {
	if section == nil {
		return nilString()
	}
	cache := section.getStringCache()
	if cache == nil {
		return section.toCanonicalString(NoZone)
	}
	return cacheStr(&cache.canonicalString,
		func() string {
			return section.toCanonicalString(NoZone)
		})
}

// ToNormalizedString produces a normalized string.
//
//If this section has a prefix length, it will be included in the string.
func (section *IPv6AddressSection) ToNormalizedString() string {
	if section == nil {
		return nilString()
	}
	cache := section.getStringCache()
	if cache == nil {
		return section.toNormalizedString(NoZone)
	}
	return cacheStr(&cache.normalizedIPv6String,
		func() string {
			return section.toNormalizedString(NoZone)
		})
}

func (section *IPv6AddressSection) ToCompressedString() string {
	if section == nil {
		return nilString()
	}
	cache := section.getStringCache()
	if cache == nil {
		return section.toCompressedString(NoZone)
	}
	return cacheStr(&cache.compressedIPv6String,
		func() string {
			return section.toCompressedString(NoZone)
		})
}

// This produces the mixed IPv6/IPv4 string.  It is the shortest such string (ie fully compressed).
// For some address sections with ranges of values in the IPv4 part of the address, there is not mixed string, and an error is returned.
func (section *IPv6AddressSection) toMixedString() (string, addrerr.IncompatibleAddressError) {
	cache := section.getStringCache()
	if cache == nil {
		return section.toMixedStringZoned(NoZone)
	}
	return cacheStrErr(&cache.mixedString,
		func() (string, addrerr.IncompatibleAddressError) {
			return section.toMixedStringZoned(NoZone)
		})
}

func (section *IPv6AddressSection) ToNormalizedWildcardString() string {
	if section == nil {
		return nilString()
	}
	cache := section.getStringCache()
	if cache == nil {
		return section.toNormalizedWildcardStringZoned(NoZone)
	}
	return cacheStr(&cache.normalizedWildcardString,
		func() string {
			return section.toNormalizedWildcardStringZoned(NoZone)
		})
}

func (section *IPv6AddressSection) ToCanonicalWildcardString() string {
	if section == nil {
		return nilString()
	}
	cache := section.getStringCache()
	if cache == nil {
		return section.toCanonicalWildcardStringZoned(NoZone)
	}
	return cacheStr(&cache.canonicalWildcardString,
		func() string {
			return section.toCanonicalWildcardStringZoned(NoZone)
		})
}

func (section *IPv6AddressSection) ToSegmentedBinaryString() string {
	if section == nil {
		return nilString()
	}
	cache := section.getStringCache()
	if cache == nil {
		return section.toSegmentedBinaryStringZoned(NoZone)
	}
	return cacheStr(&cache.segmentedBinaryString,
		func() string {
			return section.toSegmentedBinaryStringZoned(NoZone)
		})
}

func (section *IPv6AddressSection) ToSQLWildcardString() string {
	if section == nil {
		return nilString()
	}
	cache := section.getStringCache()
	if cache == nil {
		return section.toSQLWildcardStringZoned(NoZone)
	}
	return cacheStr(&cache.sqlWildcardString,
		func() string {
			return section.toSQLWildcardStringZoned(NoZone)
		})
}

func (section *IPv6AddressSection) ToFullString() string {
	if section == nil {
		return nilString()
	}
	cache := section.getStringCache()
	if cache == nil {
		return section.toFullStringZoned(NoZone)
	}
	return cacheStr(&cache.fullString,
		func() string {
			return section.toFullStringZoned(NoZone)
		})
}

func (section *IPv6AddressSection) ToReverseDNSString() (string, addrerr.IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	cache := section.getStringCache()
	if cache == nil {
		return section.toReverseDNSStringZoned(NoZone)
	}
	return cacheStrErr(&cache.reverseDNSString,
		func() (string, addrerr.IncompatibleAddressError) {
			return section.toReverseDNSStringZoned(NoZone)
		})
}

func (section *IPv6AddressSection) ToPrefixLenString() string {
	if section == nil {
		return nilString()
	}
	cache := section.getStringCache()
	if cache == nil {
		return section.toPrefixLenStringZoned(NoZone)
	}
	return cacheStr(&cache.networkPrefixLengthString,
		func() string {
			return section.toPrefixLenStringZoned(NoZone)
		})
}

func (section *IPv6AddressSection) ToSubnetString() string {
	if section == nil {
		return nilString()
	}
	return section.ToPrefixLenString()
}

func (section *IPv6AddressSection) ToCompressedWildcardString() string {
	if section == nil {
		return nilString()
	}
	cache := section.getStringCache()
	if cache == nil {
		return section.toCompressedWildcardStringZoned(NoZone)
	}
	return cacheStr(&cache.compressedWildcardString,
		func() string {
			return section.toCompressedWildcardStringZoned(NoZone)
		})
}

func (section *IPv6AddressSection) toCanonicalString(zone Zone) string {
	return section.toNormalizedZonedString(ipv6CanonicalParams, zone)
}

func (section *IPv6AddressSection) toNormalizedString(zone Zone) string {
	return section.toNormalizedZonedString(ipv6normalizedParams, zone)
}

func (section *IPv6AddressSection) toCompressedString(zone Zone) string {
	return section.toNormalizedZonedString(ipv6CompressedParams, zone)
}

func (section *IPv6AddressSection) toMixedStringZoned(zone Zone) (string, addrerr.IncompatibleAddressError) {
	return section.toNormalizedMixedZonedString(mixedParams, zone)
}

func (section *IPv6AddressSection) toNormalizedWildcardStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(ipv6NormalizedWildcardParams, zone)
}

func (section *IPv6AddressSection) toCanonicalWildcardStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(canonicalWildcardParams, zone)
}

func (section *IPv6AddressSection) toSegmentedBinaryStringZoned(zone Zone) string {
	return section.ipAddressSectionInternal.toCustomZonedString(ipv6SegmentedBinaryParams, zone)
}

func (section *IPv6AddressSection) toSQLWildcardStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(ipv6SqlWildcardParams, zone)
}

func (section *IPv6AddressSection) toFullStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(ipv6FullParams, zone)
}

func (section *IPv6AddressSection) toReverseDNSStringZoned(zone Zone) (string, addrerr.IncompatibleAddressError) {
	return section.toNormalizedSplitZonedString(ipv6ReverseDNSParams, zone)
}

func (section *IPv6AddressSection) toPrefixLenStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(networkPrefixLengthParams, zone)
}

func (section *IPv6AddressSection) toCompressedWildcardStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(wildcardCompressedParams, zone)
}

// ToCustomString produces a string given the string options.
// Errors can result from split digits with ranged values, or mixed IPv4/v6 with ranged values, when the segment ranges are incompatible.
func (section *IPv6AddressSection) ToCustomString(stringOptions addrstr.IPv6StringOptions) (string, addrerr.IncompatibleAddressError) {
	if section == nil {
		return nilString(), nil
	}
	return section.toCustomString(stringOptions, NoZone)
}

func (section *IPv6AddressSection) toCustomString(stringOptions addrstr.IPv6StringOptions, zone Zone) (string, addrerr.IncompatibleAddressError) {
	if stringOptions.IsMixed() {
		return section.toNormalizedMixedZonedString(stringOptions, zone)
	} else if stringOptions.IsSplitDigits() {
		return section.toNormalizedSplitZonedString(stringOptions, zone)
	}
	return section.toNormalizedZonedString(stringOptions, zone), nil
}

func (section *IPv6AddressSection) toNormalizedZonedString(options addrstr.IPv6StringOptions, zone Zone) string {
	var stringParams *ipv6StringParams
	if isCacheable(options) { // the isCacheable call is key and determines if the IPv6StringParams can be shared
		opts, hasCache := options.(ipv6CacheAccess)
		if hasCache {
			cached := opts.GetIPv6StringOptionsCache()
			stringParams = (*ipv6StringParams)(*cached)
		}
		if stringParams == nil {
			stringParams = from(options, section)
			if hasCache {
				dataLoc := opts.GetIPv6StringOptionsCache()
				atomic.StorePointer(dataLoc, unsafe.Pointer(stringParams))
			}
		}
	} else {
		stringParams = from(options, section)
	}
	return stringParams.toZonedString(section, zone)
}

type ipv6CacheAccess interface {
	GetIPv6StringOptionsCache() *unsafe.Pointer

	GetIPv6StringOptionsMixedCache() *unsafe.Pointer
}

func (section *IPv6AddressSection) toNormalizedSplitZonedString(options addrstr.IPv6StringOptions, zone Zone) (string, addrerr.IncompatibleAddressError) {
	var stringParams *ipv6StringParams
	// all split strings are cacheable since no compression
	opts, hasCache := options.(ipv6CacheAccess)
	if hasCache {
		cached := opts.GetIPv6StringOptionsCache()
		stringParams = (*ipv6StringParams)(*cached)
	}
	if stringParams == nil {
		stringParams = from(options, section)
		if hasCache {
			dataLoc := opts.GetIPv6StringOptionsCache()
			atomic.StorePointer(dataLoc, unsafe.Pointer(stringParams))
		}
	}
	return stringParams.toZonedSplitString(section, zone)
}

func (section *IPv6AddressSection) toNormalizedMixedZonedString(options addrstr.IPv6StringOptions, zone Zone) (string, addrerr.IncompatibleAddressError) {
	var stringParams *ipv6StringParams
	if isCacheable(options) { // the isCacheable call is key and determines if the IPv6StringParams can be shared (right not it just means not compressed)
		opts, hasCache := options.(ipv6CacheAccess)
		var mixedParams *ipv6v4MixedParams
		if hasCache {
			cached := opts.GetIPv6StringOptionsMixedCache()
			mixedParams = (*ipv6v4MixedParams)(*cached)
		}
		if mixedParams == nil {
			stringParams = from(options, section)
			mixedParams = &ipv6v4MixedParams{
				ipv6Params: stringParams,
				ipv4Params: toIPParams(options.GetIPv4Opts()),
			}
			dataLoc := opts.GetIPv6StringOptionsMixedCache()
			atomic.StorePointer(dataLoc, unsafe.Pointer(mixedParams))
		}
		return section.toNormalizedMixedString(mixedParams, zone)
	}
	//no caching is possible due to the compress options
	stringParams = from(options, section)
	if stringParams.nextUncompressedIndex <= IPv6MixedOriginalSegmentCount { //the mixed section is not compressed
		//if stringParams.nextUncompressedIndex <= int(IPv6MixedOriginalSegmentCount-section.addressSegmentIndex) { //the mixed section is not compressed
		mixedParams := &ipv6v4MixedParams{
			ipv6Params: stringParams,
			ipv4Params: toIPParams(options.GetIPv4Opts()),
		}
		return section.toNormalizedMixedString(mixedParams, zone)
	}
	// the mixed section is compressed
	return stringParams.toZonedString(section, zone), nil
}

func isCacheable(options addrstr.IPv6StringOptions) bool {
	return options.GetCompressOptions() == nil
}

func (section *IPv6AddressSection) toNormalizedMixedString(mixedParams *ipv6v4MixedParams, zone Zone) (string, addrerr.IncompatibleAddressError) {
	mixed, err := section.getMixedAddressGrouping()
	if err != nil {
		return "", err
	}
	result := mixedParams.toZonedString(mixed, zone)
	return result, nil
}

func (section *IPv6AddressSection) GetSegmentStrings() []string {
	if section == nil {
		return nil
	}
	return section.getSegmentStrings()
}

func (section *IPv6AddressSection) ToDivGrouping() *AddressDivisionGrouping {
	return section.ToSectionBase().ToDivGrouping()
}

func (section *IPv6AddressSection) ToSectionBase() *AddressSection {
	return section.ToIP().ToSectionBase()
}

func (section *IPv6AddressSection) ToIP() *IPAddressSection {
	return (*IPAddressSection)(section)
}

func (section *IPv6AddressSection) getMixedAddressGrouping() (*IPv6v4MixedAddressGrouping, addrerr.IncompatibleAddressError) {
	cache := section.cache
	var sect *IPv6v4MixedAddressGrouping
	if cache != nil && cache.mixed != nil {
		sect = cache.mixed.defaultMixedAddressSection
	}
	if sect == nil {
		mixedSect, err := section.createEmbeddedIPv4AddressSection()
		if err != nil {
			return nil, err
		}
		sect = newIPv6v4MixedGrouping(
			section.createNonMixedSection(),
			mixedSect,
		)
		if cache != nil && cache.mixed != nil {
			mixed := &mixedCache{
				defaultMixedAddressSection: sect,
				embeddedIPv6Section:        sect.GetIPv6AddressSection(),
				embeddedIPv4Section:        sect.GetIPv4AddressSection(),
			}
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.mixed))
			atomic.StorePointer(dataLoc, unsafe.Pointer(mixed))
		}
	}
	return sect, nil
}

// Gets the IPv4 section corresponding to the lowest (least-significant) 4 bytes in the original address,
// which will correspond to between 0 and 4 bytes in this address.  Many IPv4 to IPv6 mapping schemes (but not all) use these 4 bytes for a mapped IPv4 address.
func (section *IPv6AddressSection) getEmbeddedIPv4AddressSection() (*IPv4AddressSection, addrerr.IncompatibleAddressError) {
	cache := section.cache
	if cache == nil {
		return section.createEmbeddedIPv4AddressSection()
	}
	sect, err := section.getMixedAddressGrouping()
	if err != nil {
		return nil, err
	}
	return sect.GetIPv4AddressSection(), nil
}

// GetIPv4AddressSection produces an IPv4 address section from a sequence of bytes in this IPv6 address section
func (section *IPv6AddressSection) GetIPv4AddressSection(startByteIndex, endByteIndex int) (*IPv4AddressSection, addrerr.IncompatibleAddressError) {
	if startByteIndex == IPv6MixedOriginalSegmentCount<<1 && endByteIndex == (section.GetSegmentCount()<<1) {
		return section.getEmbeddedIPv4AddressSection()
	}
	segments := make([]*AddressDivision, endByteIndex-startByteIndex)
	i := startByteIndex
	j := 0
	bytesPerSegment := section.GetBytesPerSegment()
	if i%bytesPerSegment == 1 {
		ipv6Segment := section.GetSegment(i >> 1)
		i++
		if err := ipv6Segment.splitIntoIPv4Segments(segments, j-1); err != nil {
			return nil, err
		}
		j++
	}
	for ; i < endByteIndex; i, j = i+bytesPerSegment, j+bytesPerSegment {
		ipv6Segment := section.GetSegment(i >> 1)
		if err := ipv6Segment.splitIntoIPv4Segments(segments, j); err != nil {
			return nil, err
		}
	}
	res := createIPv4Section(segments)
	res.initMultAndPrefLen()
	return res, nil
}

func (section *IPv6AddressSection) createNonMixedSection() *EmbeddedIPv6AddressSection {
	nonMixedCount := IPv6MixedOriginalSegmentCount
	mixedCount := section.GetSegmentCount() - nonMixedCount
	var result *IPv6AddressSection
	if mixedCount <= 0 {
		result = section
	} else {
		nonMixed := make([]*AddressDivision, nonMixedCount)
		section.copySubSegmentsToSlice(0, nonMixedCount, nonMixed)
		result = createIPv6Section(nonMixed)
		result.initMultAndPrefLen()
	}
	return &EmbeddedIPv6AddressSection{
		embeddedIPv6AddressSection: embeddedIPv6AddressSection{result},
		encompassingSection:        section,
	}
}

type embeddedIPv6AddressSection struct {
	*IPv6AddressSection
}

type EmbeddedIPv6AddressSection struct {
	embeddedIPv6AddressSection
	encompassingSection *IPv6AddressSection
}

func (section *EmbeddedIPv6AddressSection) IsPrefixBlock() bool {
	return section.encompassingSection.IsPrefixBlock()
}

func (section *IPv6AddressSection) createEmbeddedIPv4AddressSection() (sect *IPv4AddressSection, err addrerr.IncompatibleAddressError) {
	nonMixedCount := IPv6MixedOriginalSegmentCount
	segCount := section.GetSegmentCount()
	mixedCount := segCount - nonMixedCount
	lastIndex := segCount - 1
	var mixed []*AddressDivision
	if mixedCount == 0 {
		mixed = []*AddressDivision{}
	} else if mixedCount == 1 {
		mixed = make([]*AddressDivision, section.GetBytesPerSegment())
		last := section.GetSegment(lastIndex)
		if err := last.splitIntoIPv4Segments(mixed, 0); err != nil {
			return nil, err
		}
	} else {
		bytesPerSeg := section.GetBytesPerSegment()
		mixed = make([]*AddressDivision, bytesPerSeg<<1)
		low := section.GetSegment(lastIndex)
		high := section.GetSegment(lastIndex - 1)
		if err := high.splitIntoIPv4Segments(mixed, 0); err != nil {
			return nil, err
		}
		if err := low.splitIntoIPv4Segments(mixed, bytesPerSeg); err != nil {
			return nil, err
		}
	}
	sect = createIPv4Section(mixed)
	sect.initMultAndPrefLen()
	return
}

func createMixedAddressGrouping(divisions []*AddressDivision, mixedCache *mixedCache) *IPv6v4MixedAddressGrouping {
	grouping := &IPv6v4MixedAddressGrouping{
		addressDivisionGroupingInternal: addressDivisionGroupingInternal{
			addressDivisionGroupingBase: addressDivisionGroupingBase{
				divisions: standardDivArray{divisions},
				addrType:  ipv6v4MixedType,
				cache:     &valueCache{mixed: mixedCache},
			},
		},
	}
	ipv6Section := mixedCache.embeddedIPv6Section
	ipv4Section := mixedCache.embeddedIPv4Section
	grouping.isMult = ipv6Section.isMultiple() || ipv4Section.isMultiple()
	if ipv6Section.IsPrefixed() {
		grouping.prefixLength = ipv6Section.getPrefixLen()
	} else if ipv4Section.IsPrefixed() {
		grouping.prefixLength = cacheBitCount(ipv6Section.GetBitCount() + ipv4Section.getPrefixLen().bitCount())
	}
	return grouping
}

func newIPv6v4MixedGrouping(ipv6Section *EmbeddedIPv6AddressSection, ipv4Section *IPv4AddressSection) *IPv6v4MixedAddressGrouping {
	ipv6Len := ipv6Section.GetSegmentCount()
	ipv4Len := ipv4Section.GetSegmentCount()
	allSegs := make([]*AddressDivision, ipv6Len+ipv4Len)
	ipv6Section.copySubSegmentsToSlice(0, ipv6Len, allSegs)
	ipv4Section.copySubSegmentsToSlice(0, ipv4Len, allSegs[ipv6Len:])
	grouping := createMixedAddressGrouping(allSegs, &mixedCache{
		embeddedIPv6Section: ipv6Section,
		embeddedIPv4Section: ipv4Section,
	})
	return grouping
}

// IPv6v4MixedAddressGrouping has divisions which are a mix of IPv6 and IPv4 divisions
type IPv6v4MixedAddressGrouping struct {
	addressDivisionGroupingInternal
}

func (grouping *IPv6v4MixedAddressGrouping) Compare(item AddressItem) int {
	return CountComparator.Compare(grouping, item)
}

func (grouping *IPv6v4MixedAddressGrouping) CompareSize(other StandardDivGroupingType) int {
	if grouping == nil {
		if other != nil && other.ToDivGrouping() != nil {
			// we have size 0, other has size >= 1
			return -1
		}
		return 0
	}
	return grouping.compareSize(other)
}

func (grouping *IPv6v4MixedAddressGrouping) GetCount() *big.Int {
	if grouping == nil {
		return bigZero()
	}
	cnt := grouping.GetIPv6AddressSection().GetCount()
	return cnt.Add(cnt, grouping.GetIPv4AddressSection().GetCount())
}

func (grouping *IPv6v4MixedAddressGrouping) IsMultiple() bool {
	return grouping != nil && grouping.isMultiple()
}

func (grouping *IPv6v4MixedAddressGrouping) IsPrefixed() bool {
	return grouping != nil && grouping.isPrefixed()
}

func (grouping *IPv6v4MixedAddressGrouping) IsAdaptiveZero() bool {
	return grouping != nil && grouping.matchesZeroGrouping()
}

func (grouping *IPv6v4MixedAddressGrouping) ToDivGrouping() *AddressDivisionGrouping {
	return (*AddressDivisionGrouping)(grouping)
}

func (grouping *IPv6v4MixedAddressGrouping) GetIPv6AddressSection() *EmbeddedIPv6AddressSection {
	return grouping.cache.mixed.embeddedIPv6Section
}

func (grouping *IPv6v4MixedAddressGrouping) GetIPv4AddressSection() *IPv4AddressSection {
	return grouping.cache.mixed.embeddedIPv4Section
}

func (grouping *IPv6v4MixedAddressGrouping) String() string {
	if grouping == nil {
		return nilString()
	}
	return grouping.toString()
}

var ffMACSeg, feMACSeg = NewMACSegment(0xff), NewMACSegment(0xfe)

func toIPv6SegmentsFromEUI(
	segments []*AddressDivision,
	ipv6StartIndex int, // the index into the IPv6 segment array to put the MACSize-based IPv6 segments
	eui *MACAddressSection, // must be full 6 or 8 mac sections
	prefixLength PrefixLen) addrerr.IncompatibleAddressError {
	euiSegmentIndex := 0
	var seg3, seg4 *MACAddressSegment
	var err addrerr.IncompatibleAddressError
	seg0 := eui.GetSegment(euiSegmentIndex)
	euiSegmentIndex++
	seg1 := eui.GetSegment(euiSegmentIndex)
	euiSegmentIndex++
	seg2 := eui.GetSegment(euiSegmentIndex)
	euiSegmentIndex++
	isExtended := eui.GetSegmentCount() == ExtendedUniqueIdentifier64SegmentCount
	if isExtended {
		seg3 = eui.GetSegment(euiSegmentIndex)
		euiSegmentIndex++
		if !seg3.matches(0xff) {
			return &incompatibleAddressError{addressError{key: "ipaddress.mac.error.not.eui.convertible"}}
		}
		seg4 = eui.GetSegment(euiSegmentIndex)
		euiSegmentIndex++
		if !seg4.matches(0xfe) {
			return &incompatibleAddressError{addressError{key: "ipaddress.mac.error.not.eui.convertible"}}
		}
	} else {
		seg3 = ffMACSeg
		seg4 = feMACSeg
	}
	seg5 := eui.GetSegment(euiSegmentIndex)
	euiSegmentIndex++
	seg6 := eui.GetSegment(euiSegmentIndex)
	euiSegmentIndex++
	seg7 := eui.GetSegment(euiSegmentIndex)
	var currentPrefix PrefixLen
	if prefixLength != nil {
		//since the prefix comes from the ipv6 section and not the MACSize section, any segment prefix for the MACSize section is 0 or null
		//prefixes across segments have the pattern: null, null, ..., null, 0-16, 0, 0, ..., 0
		//So if the overall prefix is 0, then the prefix of every segment is 0
		currentPrefix = cacheBitCount(0)
	}
	var seg *IPv6AddressSegment
	if seg, err = seg0.joinAndFlip2ndBit(seg1, currentPrefix); /* only this first one gets the flipped bit */ err == nil {
		segments[ipv6StartIndex] = seg.ToDiv()
		ipv6StartIndex++
		if seg, err = seg2.join(seg3, currentPrefix); err == nil {
			segments[ipv6StartIndex] = seg.ToDiv()
			ipv6StartIndex++
			if seg, err = seg4.join(seg5, currentPrefix); err == nil {
				segments[ipv6StartIndex] = seg.ToDiv()
				ipv6StartIndex++
				if seg, err = seg6.join(seg7, currentPrefix); err == nil {
					segments[ipv6StartIndex] = seg.ToDiv()
					return nil
				}
			}
		}
	}
	return err
}

type Range struct {
	index, length int
}

type RangeList struct {
	ranges []Range
}

func (list RangeList) size() int {
	return len(list.ranges)
}

func (list RangeList) getRange(index int) Range {
	return list.ranges[index]
}
