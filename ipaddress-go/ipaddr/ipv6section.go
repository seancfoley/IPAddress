package ipaddr

import (
	"math/big"
	"sync/atomic"
	"unsafe"
)

func createIPv6Section(segments []*AddressDivision, startIndex int8) *IPv6AddressSection {
	return &IPv6AddressSection{
		ipAddressSectionInternal{
			addressSectionInternal{
				addressDivisionGroupingInternal{
					addressDivisionGroupingBase: addressDivisionGroupingBase{
						divisions: standardDivArray{segments},
						cache: &valueCache{
							stringCache: stringCache{
								ipv6StringCache: &ipv6StringCache{},
								ipStringCache:   &ipStringCache{},
							},
						},
						addrType: ipv6Type,
					},
					addressSegmentIndex: startIndex,
				},
			},
		},
	}
}

func newIPv6AddressSection(segments []*AddressDivision, startIndex int /*, cloneSegments bool*/, normalizeSegments bool) (res *IPv6AddressSection, err AddressValueError) {
	if startIndex < 0 {
		err = &addressPositionError{addressValueError{val: startIndex, addressError: addressError{key: "ipaddress.error.invalid.position"}}}
		return
	}
	segsLen := len(segments)
	if startIndex+segsLen > IPv6SegmentCount {
		err = &addressValueError{val: startIndex + segsLen, addressError: addressError{key: "ipaddress.error.exceeds.size"}}
		return
	}
	res = createIPv6Section(segments, int8(startIndex))
	if err = res.init(); err != nil {
		res = nil
		return
	}
	prefLen := res.prefixLength
	if normalizeSegments && prefLen != nil {
		normalizePrefixBoundary(*prefLen, segments, IPv6BitsPerSegment, IPv6BytesPerSegment, func(val, upperVal SegInt, prefLen PrefixLen) *AddressDivision {
			return NewIPv6RangePrefixSegment(IPv6SegInt(val), IPv6SegInt(upperVal), prefLen).ToAddressDivision()
		})
	}
	return
}

func newIPv6AddressSectionParsed(segments []*AddressDivision) (res *IPv6AddressSection) {
	res = createIPv6Section(segments, 0)
	_ = res.init()
	return
}

func newIPv6AddressSectionSingle(segments []*AddressDivision, startIndex int /*cloneSegments bool,*/, prefixLength PrefixLen, singleOnly bool) (res *IPv6AddressSection, err AddressValueError) {
	res, err = newIPv6AddressSection(segments, startIndex /*cloneSegments,*/, prefixLength == nil /* no need to normalize segment prefix lens if we are supplying a prefix len */)
	if err == nil && prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIPAddressSection(), singleOnly, BitCount(len(segments)<<4), IPv6BitCount)
	}
	return
}

func NewIPv6AddressSectionFromBytes(bytes []byte) (res *IPv6AddressSection, err AddressValueError) {
	return newIPv6AddressSectionFromBytes(bytes, len(bytes), nil, false)
}

// Useful if the byte array has leading zeros or leading sign extension
func NewIPv6AddressSectionFromSegmentedBytes(bytes []byte, segmentCount int) (res *IPv6AddressSection, err AddressValueError) {
	return newIPv6AddressSectionFromBytes(bytes, segmentCount, nil, false)
}

func NewIPv6AddressSectionFromPrefixedBytes(bytes []byte, segmentCount int, prefixLength PrefixLen) (res *IPv6AddressSection, err AddressValueError) {
	return newIPv6AddressSectionFromBytes(bytes, segmentCount, prefixLength, false)
}

func newIPv6AddressSectionFromBytes(bytes []byte, segmentCount int, prefixLength PrefixLen, singleOnly bool) (res *IPv6AddressSection, err AddressValueError) {
	if segmentCount < 0 {
		segmentCount = len(bytes)
	}
	expectedByteCount := segmentCount << 1
	segments, err := toSegments(
		bytes,
		segmentCount,
		IPv6BytesPerSegment,
		IPv6BitsPerSegment,
		expectedByteCount,
		DefaultIPv6Network.GetIPv6AddressCreator(),
		prefixLength)
	if err == nil {
		res = createIPv6Section(segments, 0)
		if prefixLength != nil {
			assignPrefix(prefixLength, segments, res.ToIPAddressSection(), singleOnly, BitCount(segmentCount<<3), IPv4BitCount)
		}
		if expectedByteCount == len(bytes) {
			bytes = cloneBytes(bytes)
			res.cache.bytesCache = &bytesCache{lowerBytes: bytes}
			if !res.isMultiple { // not a prefix block
				res.cache.bytesCache.upperBytes = bytes
			}
		}
	}
	return
}

func NewIPv6AddressSectionFromValues(vals SegmentValueProvider, segmentCount int) (res *IPv6AddressSection) {
	res = NewIPv6AddressSectionFromPrefixedRangeValues(vals, nil, segmentCount, nil)
	return
}

func NewIPv6AddressSectionFromPrefixedValues(vals SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv6AddressSection) {
	return NewIPv6AddressSectionFromPrefixedRangeValues(vals, nil, segmentCount, prefixLength)
}

func NewIPv6AddressSectionFromRangeValues(vals, upperVals SegmentValueProvider, segmentCount int) (res *IPv6AddressSection) {
	res = NewIPv6AddressSectionFromPrefixedRangeValues(vals, upperVals, segmentCount, nil)
	return
}

func NewIPv6AddressSectionFromPrefixedRangeValues(vals, upperVals SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv6AddressSection) {
	if segmentCount < 0 {
		segmentCount = 0
	}
	segments, isMultiple := createSegments(
		vals, upperVals,
		segmentCount,
		IPv6BitsPerSegment,
		DefaultIPv6Network.GetIPv6AddressCreator(),
		prefixLength)
	res = createIPv6Section(segments, 0)
	res.isMultiple = isMultiple
	if prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIPAddressSection(), false, BitCount(segmentCount<<3), IPv6BitCount)
	}
	return
}

// IPv6AddressSection represents a section of an IPv6 address comprising 0 to 8 IPv6 address segments.
// The zero values is a section with zero segments.
type IPv6AddressSection struct {
	ipAddressSectionInternal
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
	return section.cacheCount(func() *big.Int {
		return count(func(index int) uint64 {
			return section.GetSegment(index).GetValueCount()
		}, section.GetSegmentCount(), 2, 0x7fffffffffff)
	})
}

func (section *IPv6AddressSection) GetPrefixCount() *big.Int {
	return section.cachePrefixCount(func() *big.Int {
		return section.GetPrefixCountLen(*section.GetPrefixLength())
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
		}, networkSegmentIndex+1, 2, 0x7fffffffffff)
	})
}

//func (section *IPv6AddressSection) CompareSize(other *IPv6AddressSection) int {
//	return section.CompareSize(other.ToIPAddressSection())
//}

func (section *IPv6AddressSection) GetSegment(index int) *IPv6AddressSegment {
	return section.getDivision(index).ToIPv6AddressSegment()
}

// Gets the subsection from the series starting from the given index
// The first segment is at index 0.
func (section *IPv6AddressSection) GetTrailingSection(index int) *IPv6AddressSection {
	return section.GetSubSection(index, section.GetSegmentCount())
}

//// Gets the subsection from the series starting from the given index and ending just before the give endIndex
//// The first segment is at index 0.
func (section *IPv6AddressSection) GetSubSection(index, endIndex int) *IPv6AddressSection {
	return section.getSubSection(index, endIndex).ToIPv6AddressSection()
}

func (section *IPv6AddressSection) GetNetworkSection() *IPv6AddressSection {
	return section.getNetworkSection().ToIPv6AddressSection()
}

func (section *IPv6AddressSection) GetNetworkSectionLen(prefLen BitCount) *IPv6AddressSection {
	return section.getNetworkSectionLen(prefLen).ToIPv6AddressSection()
}

func (section *IPv6AddressSection) GetHostSection() *IPv6AddressSection {
	return section.getHostSection().ToIPv6AddressSection()
}

func (section *IPv6AddressSection) GetHostSectionLen(prefLen BitCount) *IPv6AddressSection {
	return section.getHostSectionLen(prefLen).ToIPv6AddressSection()
}

func (section *IPv6AddressSection) GetNetworkMask() *IPv6AddressSection {
	return section.getNetworkMask(DefaultIPv6Network).ToIPv6AddressSection()
}

func (section *IPv6AddressSection) GetHostMask() *IPv6AddressSection {
	return section.getHostMask(DefaultIPv6Network).ToIPv6AddressSection()
}

//// ForEachSegment calls the given callback for each segment, terminating early if a callback returns true TODO not sure about this, still considering adding it (here and in Java), it allows you to avoid panics by not going past end of segment array
//func (section *IPv6AddressSection) ForEachSegment(callback func(index int, segment *IPv6AddressSegment) (stop bool)) {
//	section.visitSegments(
//		func(index int, div *AddressDivision) bool {
//			return callback(index, div.ToIPv6AddressSegment())
//		},
//		section.GetSegmentCount())
//}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *IPv6AddressSection) CopySubSegments(start, end int, segs []*IPv6AddressSegment) (count int) {
	return section.visitSubSegments(start, end, func(index int, div *AddressDivision) bool { segs[index] = div.ToIPv6AddressSegment(); return false }, len(segs))
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *IPv6AddressSection) CopySegments(segs []*IPv6AddressSegment) (count int) {
	return section.visitSegments(func(index int, div *AddressDivision) bool { segs[index] = div.ToIPv6AddressSegment(); return false }, len(segs))
}

// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this section.
func (section *IPv6AddressSection) GetSegments() (res []*IPv6AddressSegment) {
	res = make([]*IPv6AddressSegment, section.GetSegmentCount())
	section.CopySegments(res)
	return
}

func (section *IPv6AddressSection) Mask(other *IPv6AddressSection) (res *IPv6AddressSection, err IncompatibleAddressError) {
	return section.MaskPrefixed(other, false)
}

func (section *IPv6AddressSection) MaskPrefixed(other *IPv6AddressSection, retainPrefix bool) (res *IPv6AddressSection, err IncompatibleAddressError) {
	sec, err := section.mask(other.ToIPAddressSection(), retainPrefix)
	if err == nil {
		res = sec.ToIPv6AddressSection()
	}
	return
}

func (section *IPv6AddressSection) GetLower() *IPv6AddressSection {
	return section.getLower().ToIPv6AddressSection()
}

func (section *IPv6AddressSection) GetUpper() *IPv6AddressSection {
	return section.getUpper().ToIPv6AddressSection()
}

func (section *IPv6AddressSection) ToZeroHost() (*IPv6AddressSection, IncompatibleAddressError) {
	res, err := section.toZeroHost()
	return res.ToIPv6AddressSection(), err
}

func (section *IPv6AddressSection) ToZeroHostLen(prefixLength BitCount) (*IPv6AddressSection, IncompatibleAddressError) {
	res, err := section.toZeroHostLen(prefixLength)
	return res.ToIPv6AddressSection(), err
}

func (section *IPv6AddressSection) ToZeroNetwork() *IPv6AddressSection {
	return section.toZeroNetwork().ToIPv6AddressSection()
}

func (section *IPv6AddressSection) ToMaxHost() (*IPv6AddressSection, IncompatibleAddressError) {
	res, err := section.toMaxHost()
	return res.ToIPv6AddressSection(), err
}

func (section *IPv6AddressSection) ToMaxHostLen(prefixLength BitCount) (*IPv6AddressSection, IncompatibleAddressError) {
	res, err := section.toMaxHostLen(prefixLength)
	return res.ToIPv6AddressSection(), err
}

func (section *IPv6AddressSection) ToPrefixBlock() *IPv6AddressSection {
	return section.toPrefixBlock().ToIPv6AddressSection()
}

func (section *IPv6AddressSection) ToPrefixBlockLen(prefLen BitCount) *IPv6AddressSection {
	return section.toPrefixBlockLen(prefLen).ToIPv6AddressSection()
}

func (section *IPv6AddressSection) ToBlock(segmentIndex int, lower, upper SegInt) *IPv6AddressSection {
	return section.toBlock(segmentIndex, lower, upper).ToIPv6AddressSection()
}

func (section *IPv6AddressSection) WithoutPrefixLen() *IPv6AddressSection {
	return section.withoutPrefixLen().ToIPv6AddressSection()
}

func (section *IPv6AddressSection) SetPrefixLen(prefixLen BitCount) *IPv6AddressSection {
	return section.setPrefixLen(prefixLen).ToIPv6AddressSection()
}

func (section *IPv6AddressSection) SetPrefixLenZeroed(prefixLen BitCount) (*IPv6AddressSection, IncompatibleAddressError) {
	res, err := section.setPrefixLenZeroed(prefixLen)
	return res.ToIPv6AddressSection(), err
}

func (section *IPv6AddressSection) AssignPrefixForSingleBlock() *IPv6AddressSection {
	return section.assignPrefixForSingleBlock().ToIPv6AddressSection()
}

func (section *IPv6AddressSection) AssignMinPrefixForBlock() *IPv6AddressSection {
	return section.assignMinPrefixForBlock().ToIPv6AddressSection()
}

func (section *IPv6AddressSection) Iterator() IPv6SectionIterator {
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
		return nil
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
func (section *IPv6AddressSection) getCompressIndexAndCount(options CompressOptions, createMixed bool) (maxIndex, maxCount int) {
	if options != nil {
		rangeSelection := options.GetCompressionChoiceOptions()
		var compressibleSegs RangeList
		if rangeSelection.compressHost() {
			compressibleSegs = section.GetZeroRangeSegments()
		} else {
			compressibleSegs = section.GetZeroSegments()
		}
		maxCount = 0
		segmentCount := section.GetSegmentCount()
		compressMixed := createMixed && options.GetMixedCompressionOptions().compressMixed(section)
		preferHost := (rangeSelection == HOST_PREFERRED)
		preferMixed := createMixed && (rangeSelection == MIXED_PREFERRED)
		for i := compressibleSegs.size() - 1; i >= 0; i-- {
			rng := compressibleSegs.getRange(i)
			index := rng.index
			count := rng.length
			if createMixed {
				//so here we shorten the range to exclude the mixed part if necessary
				mixedIndex := int(IPv6MixedOriginalSegmentCount - section.addressSegmentIndex)
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
				(BitCount(index+count)*section.GetBitsPerSegment()) > *section.GetNetworkPrefixLength() { //this range contains the host
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

func (section *IPv6AddressSection) getZeroSegments(includeRanges bool) RangeList {
	divisionCount := section.GetSegmentCount()
	isFullRangeHost := section.IsPrefixBlock()
	includeRanges = includeRanges && isFullRangeHost
	var currentIndex, currentCount, rangeCount int
	var ranges [IPv6SegmentCount >> 1]Range
	for i := 0; i < divisionCount; i++ {
		division := section.GetSegment(i)
		isCompressible := division.IsZero() ||
			(includeRanges && division.IsPrefixed() && division.isSinglePrefixBlock(0, division.getUpperDivisionValue(), *division.getDivisionPrefixLength()))
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
	return section.incrementBoundary(increment).ToIPv6AddressSection()
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
	if increment == 0 && !section.IsMultiple() {
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
	prefixLength := section.GetPrefixLength()
	result := fastIncrement(
		section.ToAddressSection(),
		increment,
		DefaultIPv6Network.GetIPv6AddressCreator(),
		section.getLower,
		section.getUpper,
		prefixLength)
	if result != nil {
		return result.ToIPv6AddressSection()
	}
	bigIncrement.SetInt64(increment)
	return incrementBig(
		section.ToAddressSection(),
		increment,
		&bigIncrement,
		DefaultIPv6Network.GetIPv6AddressCreator(),
		section.getLower,
		section.getUpper,
		prefixLength).ToIPv6AddressSection()
}

func (section *IPv6AddressSection) SpanWithPrefixBlocks() []*IPv6AddressSection {
	if section.IsSequential() {
		if section.IsSinglePrefixBlock() {
			return []*IPv6AddressSection{section}
		}
		wrapped := WrappedIPAddressSection{section.ToIPAddressSection()}
		spanning := getSpanningPrefixBlocks(wrapped, wrapped)
		return cloneToIPv6Sections(spanning)
	}
	wrapped := WrappedIPAddressSection{section.ToIPAddressSection()}
	return cloneToIPv6Sections(spanWithPrefixBlocks(wrapped))
}

func (section *IPv6AddressSection) SpanWithPrefixBlocksTo(other *IPv6AddressSection) ([]*IPv6AddressSection, SizeMismatchError) {
	if err := section.checkSectionCount(other.ToIPAddressSection()); err != nil {
		return nil, err
	}
	return cloneToIPv6Sections(
		getSpanningPrefixBlocks(
			WrappedIPAddressSection{section.ToIPAddressSection()},
			WrappedIPAddressSection{other.ToIPAddressSection()},
		),
	), nil
}

func (section *IPv6AddressSection) SpanWithSequentialBlocks() []*IPv6AddressSection {
	if section.IsSequential() {
		return []*IPv6AddressSection{section}
	}
	wrapped := WrappedIPAddressSection{section.ToIPAddressSection()}
	return cloneToIPv6Sections(spanWithSequentialBlocks(wrapped))
}

func (section *IPv6AddressSection) SpanWithSequentialBlocksTo(other *IPv6AddressSection) ([]*IPv6AddressSection, SizeMismatchError) {
	if err := section.checkSectionCount(other.ToIPAddressSection()); err != nil {
		return nil, err
	}
	return cloneToIPv6Sections(
		getSpanningSequentialBlocks(
			WrappedIPAddressSection{section.ToIPAddressSection()},
			WrappedIPAddressSection{other.ToIPAddressSection()},
		),
	), nil
}

func (section *IPv6AddressSection) CoverWithPrefixBlockTo(other *IPv6AddressSection) (*IPv6AddressSection, SizeMismatchError) {
	res, err := section.coverWithPrefixBlockTo(other.ToIPAddressSection())
	return res.ToIPv6AddressSection(), err
}

func (section *IPv6AddressSection) CoverWithPrefixBlock() *IPv6AddressSection {
	return section.coverWithPrefixBlock().ToIPv6AddressSection()
}

//
// MergeToSequentialBlocks merges this with the list of sections to produce the smallest array of blocks that are sequential
//
// The resulting array is sorted from lowest address value to highest, regardless of the size of each prefix block.
func (section *IPv6AddressSection) MergeToSequentialBlocks(sections ...*IPv6AddressSection) ([]*IPv6AddressSection, SizeMismatchError) {
	series := cloneIPv6Sections(section, sections)
	if err := checkSectionCounts(series); err != nil {
		return nil, err
	}
	blocks := getMergedSequentialBlocks(series)
	return cloneToIPv6Sections(blocks), nil
}

//
// MergeToPrefixBlocks merges this with the list of sections to produce the smallest array of prefix blocks.
//
// The resulting array is sorted from lowest address value to highest, regardless of the size of each prefix block.
func (section *IPv6AddressSection) MergeToPrefixBlocks(sections ...*IPv6AddressSection) ([]*IPv6AddressSection, SizeMismatchError) {
	series := cloneIPv6Sections(section, sections)
	if err := checkSectionCounts(series); err != nil {
		return nil, err
	}
	blocks := getMergedPrefixBlocks(series)
	return cloneToIPv6Sections(blocks), nil
}

//
// Merges this with the list of sections to produce the smallest array of prefix blocks.
//
// The resulting array is sorted from lowest address value to highest, regardless of the size of each prefix block.
//func MergeToIPv6PrefixBlocks(sections ...*IPv6AddressSection) ([]*IPv6AddressSection, SizeMismatchError) {
//	series := cloneIPv6Sections(sections)
//	if err := checkSectionCounts(series); err != nil {
//		return nil, err
//	}
//	blocks := getMergedPrefixBlocks(series)
//	return cloneToIPv6Sections(blocks), nil
//}

var (
	compressAll            = new(CompressOptionsBuilder).SetCompressSingle(true).SetRangeSelection(ZEROS_OR_HOST).ToOptions()
	compressMixed          = new(CompressOptionsBuilder).SetCompressSingle(true).SetRangeSelection(MIXED_PREFERRED).ToOptions()
	compressAllNoSingles   = new(CompressOptionsBuilder).SetRangeSelection(ZEROS_OR_HOST).ToOptions()
	compressHostPreferred  = new(CompressOptionsBuilder).SetCompressSingle(true).SetRangeSelection(HOST_PREFERRED).ToOptions()
	compressZeros          = new(CompressOptionsBuilder).SetCompressSingle(true).SetRangeSelection(ZEROS).ToOptions()
	compressZerosNoSingles = new(CompressOptionsBuilder).SetRangeSelection(ZEROS).ToOptions()

	uncWildcards = new(WildcardOptionsBuilder).SetWildcardOptions(WILDCARDS_NETWORK_ONLY).SetWildcards(
		new(WildcardsBuilder).SetRangeSeparator(IPv6UncRangeSeparatorStr).SetWildcard(SegmentWildcardStr).ToWildcards()).ToOptions()
	base85Wildcards = new(WildcardsBuilder).SetRangeSeparator(AlternativeRangeSeparatorStr).ToWildcards()

	mixedParams         = NewIPv6StringOptionsBuilder().SetMakeMixed(true).SetCompressOptions(compressMixed).ToOptions()
	ipv6FullParams      = NewIPv6StringOptionsBuilder().SetExpandedSegments(true).SetWildcardOptions(wildcardsRangeOnlyNetworkOnly).ToOptions()
	ipv6CanonicalParams = NewIPv6StringOptionsBuilder().SetCompressOptions(compressAllNoSingles).ToOptions()
	uncParams           = NewIPv6StringOptionsBuilder().SetSeparator(IPv6UncSegmentSeparator).SetZoneSeparator(IPv6UncZoneSeparator).
				SetAddressSuffix(IPv6UncSuffix).SetWildcardOptions(uncWildcards).ToOptions()
	ipv6CompressedParams         = NewIPv6StringOptionsBuilder().SetCompressOptions(compressAll).ToOptions()
	ipv6normalizedParams         = NewIPv6StringOptionsBuilder().ToOptions()
	canonicalWildcardParams      = NewIPv6StringOptionsBuilder().SetWildcardOptions(allWildcards).SetCompressOptions(compressZerosNoSingles).ToOptions()
	ipv6NormalizedWildcardParams = NewIPv6StringOptionsBuilder().SetWildcardOptions(allWildcards).ToOptions()    //no compression
	ipv6SqlWildcardParams        = NewIPv6StringOptionsBuilder().SetWildcardOptions(allSQLWildcards).ToOptions() //no compression
	wildcardCompressedParams     = NewIPv6StringOptionsBuilder().SetWildcardOptions(allWildcards).SetCompressOptions(compressZeros).ToOptions()
	networkPrefixLengthParams    = NewIPv6StringOptionsBuilder().SetCompressOptions(compressHostPreferred).ToOptions()
	ipv6ReverseDNSParams         = NewIPv6StringOptionsBuilder().SetReverse(true).SetAddressSuffix(IPv6ReverseDnsSuffix).
					SetSplitDigits(true).SetExpandedSegments(true).SetSeparator('.').ToOptions()
	base85Params = new(IPStringOptionsBuilder).SetRadix(85).SetExpandedSegments(true).
			SetWildcards(base85Wildcards).SetZoneSeparator(IPv6AlternativeZoneSeparator).ToOptions()
	ipv6SegmentedBinaryParams = new(IPStringOptionsBuilder).SetRadix(2).SetSeparator(IPv6SegmentSeparator).SetSegmentStrPrefix(BinaryStrPrefix).
					SetExpandedSegments(true).ToOptions()
)

// ToCanonicalString produces a canonical string.
//
//If this section has a prefix length, it will be included in the string.
func (section *IPv6AddressSection) ToCanonicalString() string {
	return cacheStr(&section.getStringCache().canonicalString,
		func() string {
			return section.toCanonicalString(noZone)
		})
}

// ToNormalizedString produces a normalized string.
//
//If this section has a prefix length, it will be included in the string.
func (section *IPv6AddressSection) ToNormalizedString() string {
	return cacheStr(&section.getStringCache().normalizedIPv6String,
		func() string {
			return section.toNormalizedString(noZone)
		})
}

func (section *IPv6AddressSection) ToCompressedString() string {
	return cacheStr(&section.getStringCache().compressedIPv6String,
		func() string {
			return section.toCompressedString(noZone)
		})
}

// This produces the mixed IPv6/IPv4 string.  It is the shortest such string (ie fully compressed).
func (section *IPv6AddressSection) ToMixedString() string {
	return cacheStr(&section.getStringCache().normalizedIPv6String,
		func() string {
			return section.toMixedStringZoned(noZone)
		})
}

func (section *IPv6AddressSection) ToNormalizedWildcardString() string {
	return cacheStr(&section.getStringCache().normalizedWildcardString,
		func() string {
			return section.toNormalizedWildcardStringZoned(noZone)
		})
}

func (section *IPv6AddressSection) ToCanonicalWildcardString() string {
	return cacheStr(&section.getStringCache().canonicalWildcardString,
		func() string {
			return section.toCanonicalWildcardStringZoned(noZone)
		})
}

func (section *IPv6AddressSection) ToSegmentedBinaryString() string {
	return cacheStr(&section.getStringCache().segmentedBinaryString,
		func() string {
			return section.toSegmentedBinaryStringZoned(noZone)
		})
}

func (section *IPv6AddressSection) ToSQLWildcardString() string {
	return cacheStr(&section.getStringCache().sqlWildcardString,
		func() string {
			return section.toSQLWildcardStringZoned(noZone)
		})
}

func (section *IPv6AddressSection) ToFullString() string {
	return cacheStr(&section.getStringCache().fullString,
		func() string {
			return section.toFullStringZoned(noZone)
		})
}

func (section *IPv6AddressSection) ToReverseDNSString() string {
	return cacheStr(&section.getStringCache().reverseDNSString,
		func() string {
			return section.toReverseDNSStringZoned(noZone)
		})
}

func (section *IPv6AddressSection) ToPrefixLenString() string {
	return cacheStr(&section.getStringCache().networkPrefixLengthString,
		func() string {
			return section.toPrefixLenStringZoned(noZone)
		})
}

func (section *IPv6AddressSection) ToSubnetString() string {
	return section.ToPrefixLenString()
}

func (section *IPv6AddressSection) ToCompressedWildcardString() string {
	return cacheStr(&section.getStringCache().compressedWildcardString,
		func() string {
			return section.toCompressedWildcardStringZoned(noZone)
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

func (section *IPv6AddressSection) toMixedStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(mixedParams, zone)
}

func (section *IPv6AddressSection) toNormalizedWildcardStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(ipv6NormalizedWildcardParams, zone)
}

func (section *IPv6AddressSection) toCanonicalWildcardStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(canonicalWildcardParams, zone)
}

func (section *IPv6AddressSection) toSegmentedBinaryStringZoned(zone Zone) string {
	return section.toNormalizedIPOptsString(ipv6SegmentedBinaryParams, zone)
}

func (section *IPv6AddressSection) toSQLWildcardStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(ipv6SqlWildcardParams, zone)
}

func (section *IPv6AddressSection) toFullStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(ipv6FullParams, zone)
}

func (section *IPv6AddressSection) toReverseDNSStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(ipv6ReverseDNSParams, zone)
}

func (section *IPv6AddressSection) toPrefixLenStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(networkPrefixLengthParams, zone)
}

func (section *IPv6AddressSection) toCompressedWildcardStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(wildcardCompressedParams, zone)
}

func (section *IPv6AddressSection) toNormalizedIPOptsString(stringOptions IPStringOptions, zone Zone) string {
	return toNormalizedIPZonedString(stringOptions, section, zone)
}

func (section *IPv6AddressSection) toNormalizedZonedString(options IPv6StringOptions, zone Zone) string {
	var stringParams *ipv6StringParams
	if options.isCacheable() { // the isCacheable call is key and determines if the IPv6StringParams can be shared
		opts, hasCache := options.(*ipv6StringOptions)
		if options.makeMixed() {
			var mixedParams *ipv6v4MixedParams
			if hasCache {
				mixedParams = opts.cachedMixedIPv6Addr
			}
			if mixedParams == nil {
				stringParams = options.from(section)
				mixedParams := &ipv6v4MixedParams{
					ipv6Params: stringParams,
					ipv4Params: toIPParams(options.GetIPv4Opts()),
				}
				dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&opts.cachedMixedIPv6Addr))
				atomic.StorePointer(dataLoc, unsafe.Pointer(mixedParams))
			}
			return section.toNormalizedMixedString(mixedParams, zone)
		}
		if hasCache {
			stringParams = opts.cachedIPv6Addr
		}
		if stringParams == nil {
			stringParams = options.from(section)
			if hasCache {
				dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&opts.cachedIPv6Addr))
				atomic.StorePointer(dataLoc, unsafe.Pointer(stringParams))
			}
		}
	} else {
		//no caching is possible due to the compress options
		stringParams = options.from(section)
		if options.makeMixed() && stringParams.nextUncompressedIndex <= int(IPv6MixedOriginalSegmentCount-section.addressSegmentIndex) { //the mixed section is not compressed
			mixedParams := &ipv6v4MixedParams{
				ipv6Params: stringParams,
				ipv4Params: toIPParams(options.GetIPv4Opts()),
			}
			return section.toNormalizedMixedString(mixedParams, zone)
		}
	}
	return stringParams.toZonedString(section, zone)
}

func (section *IPv6AddressSection) toNormalizedMixedString(mixedParams *ipv6v4MixedParams, zone Zone) string {
	mixed := section.GetMixedAddressSection()
	result := mixedParams.toZonedString(mixed, zone)
	return result
}

func (section *IPv6AddressSection) ToIPAddressSection() *IPAddressSection {
	return (*IPAddressSection)(unsafe.Pointer(section))
}

func (section *IPv6AddressSection) GetMixedAddressSection() *IPv6v4MixedAddressSection {
	cache := section.cache
	var sect *IPv6v4MixedAddressSection
	if cache != nil {
		sect = cache.defaultMixedAddressSection
	}
	if sect == nil {
		sect = newIPv6v4MixedSection(
			section.createNonMixedSection(),
			section.GetEmbeddedIPv4AddressSection())
		if cache != nil {
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.defaultMixedAddressSection))
			atomic.StorePointer(dataLoc, unsafe.Pointer(sect))
		}
	}
	return sect
}

// GetIPv4AddressSection produces an IPv4 address section from any sequence of bytes in this IPv6 address section
func (section *IPv6AddressSection) GetIPv4AddressSection(startIndex, endIndex int) *IPv4AddressSection {
	addressSegmentIndex := section.addressSegmentIndex
	if startIndex == (IPv6MixedOriginalSegmentCount-int(addressSegmentIndex))<<1 && endIndex == (section.GetSegmentCount()<<1) {
		return section.GetEmbeddedIPv4AddressSection()
	}
	segments := make([]*AddressDivision, endIndex-startIndex)
	i := startIndex
	j := 0
	bytesPerSegment := section.GetBytesPerSegment()
	if i%bytesPerSegment == 1 {
		ipv6Segment := section.GetSegment(i >> 1)
		i++
		ipv6Segment.getSplitSegments(segments, j-1)
		j++
	}
	for ; i < endIndex; i, j = i+bytesPerSegment, j+bytesPerSegment {
		ipv6Segment := section.GetSegment(i >> 1)
		ipv6Segment.getSplitSegments(segments, j)
	}
	res := createIPv4Section(segments)
	res.init()
	return res
}

// Gets the IPv4 section corresponding to the lowest (least-significant) 4 bytes in the original address,
// which will correspond to between 0 and 4 bytes in this address.  Many IPv4 to IPv6 mapping schemes (but not all) use these 4 bytes for a mapped IPv4 address.

func (section *IPv6AddressSection) GetEmbeddedIPv4AddressSection() *IPv4AddressSection {
	cache := section.cache
	var sect *IPv4AddressSection
	if cache != nil {
		sect = cache.embeddedIPv4Section
	}
	if sect == nil {
		nonMixedCount := 0
		addressSegmentIndex := section.addressSegmentIndex
		if count := IPv6MixedOriginalSegmentCount - int(addressSegmentIndex); count > 0 {
			nonMixedCount = count
		}
		segCount := section.GetSegmentCount()
		mixedCount := segCount - nonMixedCount
		lastIndex := segCount - 1
		var mixed []*AddressDivision
		if mixedCount == 0 {
			mixed = []*AddressDivision{}
		} else if mixedCount == 1 {
			mixed = make([]*AddressDivision, section.GetBytesPerSegment())
			last := section.GetSegment(lastIndex)
			last.getSplitSegments(mixed, 0)
		} else {
			bytesPerSeg := section.GetBytesPerSegment()
			mixed = make([]*AddressDivision, bytesPerSeg<<1)
			low := section.GetSegment(lastIndex)
			high := section.GetSegment(lastIndex - 1)
			high.getSplitSegments(mixed, 0)
			low.getSplitSegments(mixed, bytesPerSeg)
		}
		sect = createIPv4Section(mixed)
		sect.init()
		if cache != nil {
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.embeddedIPv4Section))
			atomic.StorePointer(dataLoc, unsafe.Pointer(sect))
		}
	}
	return sect
}

func (section *IPv6AddressSection) createNonMixedSection() *IPv6AddressSection {
	nonMixedCount := 0
	addressSegmentIndex := section.addressSegmentIndex
	if count := IPv6MixedOriginalSegmentCount - int(addressSegmentIndex); count > 0 {
		nonMixedCount = count
	}
	mixedCount := section.GetSegmentCount() - nonMixedCount
	if mixedCount <= 0 {
		return section
	}
	nonMixed := make([]*AddressDivision, nonMixedCount)
	section.copySubSegmentsToSlice(0, nonMixedCount, nonMixed)
	res := createIPv6Section(nonMixed, addressSegmentIndex)
	res.init()
	return res
}

func createMixedAddressSection(divisions []*AddressDivision) *IPv6v4MixedAddressSection {
	return &IPv6v4MixedAddressSection{
		//ipAddressSectionInternal{
		//addressSectionInternal{
		addressDivisionGroupingInternal: addressDivisionGroupingInternal{
			addressDivisionGroupingBase: addressDivisionGroupingBase{
				divisions: standardDivArray{divisions},
				//addrType:  ipv6Type,
				cache: &valueCache{},
			},
		},
		//},
		//},
	}
}

//private static IPAddressDivision[] createSegments
func newIPv6v4MixedSection(ipv6Section *IPv6AddressSection, ipv4Section *IPv4AddressSection) *IPv6v4MixedAddressSection {
	//This cannot be public so we can be sure that the prefix lengths amongst the segments jive
	// also set isMultiple, prefixLength,
	//This is the first attempt to create a division grouping that has no address type.
	// So what about down-scaling?  Do we allow it?  No.  Unless we add another address type.  But then we'd need to add a ToMixedSection()
	// It just seems pointless.
	ipv6Len := ipv6Section.GetSegmentCount()
	ipv4Len := ipv4Section.GetSegmentCount()
	//if(ipv6Len + ((ipv4Len + 1) >> 1) + ipv6Section.addressSegmentIndex > IPv6SegmentCount) {
	//	throw new AddressValueError(ipv6Section, ipv4Section);
	//}
	//func (section *addressSectionInternal) copySubSegmentsToSlice(start, end int, divs []*AddressDivision) (count int) {
	allSegs := make([]*AddressDivision, ipv6Len+ipv4Len)
	ipv6Section.copySubSegmentsToSlice(0, ipv6Len, allSegs)
	ipv4Section.copySubSegmentsToSlice(0, ipv4Len, allSegs[ipv6Len:])
	section := createMixedAddressSection(allSegs)
	section.ipv6Section = ipv6Section
	section.ipv4Section = ipv4Section
	section.isMultiple = ipv6Section.IsMultiple() || ipv4Section.IsMultiple()
	if ipv6Section.IsPrefixed() {
		section.prefixLength = ipv6Section.GetPrefixLength()
	} else if ipv4Section.IsPrefixed() {
		section.prefixLength = cache(ipv6Section.GetBitCount() + *ipv4Section.GetPrefixLength())
	}
	return section
}

//TODO this can wrap AddressDivisionGrouping I guess
// but would need to override a few key methods, or maybe we can just assign them right away?
// Or maybe we do not even have to worry about them
// Only worry about isPrefixBlock, but even that I do not really need
// It may very well be that this baby needs no methods whatsoever!

type IPv6v4MixedAddressSection struct {
	addressDivisionGroupingInternal

	ipv6Section *IPv6AddressSection
	ipv4Section *IPv4AddressSection
}

//func (sect *IPv6v4MixedAddressSection) GetGenericIPDivision(index int) IPAddressGenericDivision {
//	ipv6Section := sect.ipv6Section
//	if index < ipv6Section.GetSegmentCount() {
//		return ipv6Section.GetSegment(index)
//	}
//	return sect.ipv4Section.GetSegment(index)
//}

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
