package ipaddr

import (
	"math/big"
	"sync/atomic"
	"unsafe"
)

func createIPv6Section(segments []*AddressDivision) *IPv6AddressSection {
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
				},
			},
		},
	}
}

func newIPv6Section(segments []*AddressDivision /* ,startIndex int , cloneSegments bool*/, normalizeSegments bool) (res *IPv6AddressSection, err AddressValueError) {
	//if startIndex < 0 {
	//	err = &addressPositionError{addressValueError{val: startIndex, addressError: addressError{key: "ipaddress.error.invalid.position"}}}
	//	return
	//}
	segsLen := len(segments)
	if segsLen > IPv6SegmentCount {
		err = &addressValueError{val: segsLen, addressError: addressError{key: "ipaddress.error.exceeds.size"}}
		return
	}
	res = createIPv6Section(segments)
	if err = res.initMultAndPrefLen(); err != nil {
		res = nil
		return
	}
	prefLen := res.prefixLength
	if normalizeSegments && prefLen != nil {
		normalizePrefixBoundary(*prefLen, segments, IPv6BitsPerSegment, IPv6BytesPerSegment, func(val, upperVal SegInt, prefLen PrefixLen) *AddressDivision {
			return NewIPv6RangePrefixedSegment(IPv6SegInt(val), IPv6SegInt(upperVal), prefLen).ToAddressDivision()
		})
	}
	return
}

func newIPv6SectionSimple(segments []*AddressDivision) (res *IPv6AddressSection) {
	res = createIPv6Section(segments)
	return
}

func newIPv6SectionParsed(segments []*AddressDivision) (res *IPv6AddressSection) {
	res = createIPv6Section(segments)
	_ = res.initMultAndPrefLen()
	return
}

func newIPv6SectionSingle(segments []*AddressDivision /* , startIndex int /*cloneSegments bool,*/, prefixLength PrefixLen, singleOnly bool) (res *IPv6AddressSection, err AddressValueError) {
	res, err = newIPv6Section(segments /*, startIndex /*cloneSegments,*/, prefixLength == nil /* no need to normalize segment prefix lens if we are supplying a prefix len */)
	if err == nil && prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIPAddressSection(), singleOnly, BitCount(len(segments)<<4))
	}
	return
}

func NewIPv6Section(segments []*IPv6AddressSegment) (res *IPv6AddressSection, err AddressValueError) {
	res, err = newIPv6Section(cloneIPv6SegsToDivs(segments), true)
	return
}

func NewIPv6PrefixedSection(segments []*IPv6AddressSegment, prefixLength PrefixLen) (res *IPv6AddressSection, err AddressValueError) {
	divs := cloneIPv6SegsToDivs(segments)
	res, err = newIPv6Section(divs, prefixLength == nil)
	if err == nil && prefixLength != nil {
		assignPrefix(prefixLength, divs, res.ToIPAddressSection(), false, BitCount(len(segments)<<3))
	}
	return
}

func NewIPv6SectionFromBigInt(val *big.Int, segmentCount int) (res *IPv6AddressSection, err AddressValueError) {
	return NewIPv6SectionFromSegmentedBytes(val.Bytes(), segmentCount)
}

func NewIPv6SectionFromPrefixedBigInt(val *big.Int, segmentCount int, prefixLen PrefixLen) (res *IPv6AddressSection, err AddressValueError) {
	return NewIPv6SectionFromPrefixedBytes(val.Bytes(), segmentCount, prefixLen)
}

func NewIPv6SectionFromBytes(bytes []byte) (res *IPv6AddressSection, err AddressValueError) {
	return newIPv6SectionFromBytes(bytes, len(bytes), nil, false)
}

// Useful if the byte array has leading zeros or leading sign extension
func NewIPv6SectionFromSegmentedBytes(bytes []byte, segmentCount int) (res *IPv6AddressSection, err AddressValueError) {
	return newIPv6SectionFromBytes(bytes, segmentCount, nil, false)
}

func NewIPv6SectionFromPrefixedBytes(bytes []byte, segmentCount int, prefixLength PrefixLen) (res *IPv6AddressSection, err AddressValueError) {
	return newIPv6SectionFromBytes(bytes, segmentCount, prefixLength, false)
}

func newIPv6SectionFromBytes(bytes []byte, segmentCount int, prefixLength PrefixLen, singleOnly bool) (res *IPv6AddressSection, err AddressValueError) {
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
		DefaultIPv6Network.getIPAddressCreator(),
		prefixLength)
	if err == nil {
		res = createIPv6Section(segments)
		if prefixLength != nil {
			assignPrefix(prefixLength, segments, res.ToIPAddressSection(), singleOnly, BitCount(segmentCount<<3))
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

func NewIPv6SectionFromUint64(highBytes, lowBytes uint64, segmentCount int) (res *IPv6AddressSection) {
	return NewIPv6SectionFromPrefixedUint64(highBytes, lowBytes, segmentCount, nil)
}

func NewIPv6SectionFromPrefixedUint64(highBytes, lowBytes uint64, segmentCount int, prefixLength PrefixLen) (res *IPv6AddressSection) {
	if segmentCount < 0 {
		segmentCount = IPv6SegmentCount
	}
	segments := createSegmentsUint64(
		segmentCount,
		//segments []*AddressDivision, // empty
		highBytes,
		lowBytes,
		IPv6BytesPerSegment,
		IPv6BitsPerSegment,
		DefaultIPv6Network.getIPAddressCreator(),
		prefixLength)
	//expectedByteCount := segmentCount << 1
	//segments, err := toSegments(
	//	bytes,
	//	segmentCount,
	//	IPv6BytesPerSegment,
	//	IPv6BitsPerSegment,
	//	//expectedByteCount,
	//	DefaultIPv6Network.getIPAddressCreator(),
	//	prefixLength)
	//if err == nil {
	res = createIPv6Section(segments)
	if prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIPAddressSection(), false, BitCount(segmentCount<<3))
	}
	//if expectedByteCount == len(bytes) {
	//	bytes = cloneBytes(bytes)
	//	res.cache.bytesCache = &bytesCache{lowerBytes: bytes}
	//	if !res.isMultiple { // not a prefix block
	//		res.cache.bytesCache.upperBytes = bytes
	//	}
	//}
	//}
	return
}

func NewIPv6SectionFromValues(vals SegmentValueProvider, segmentCount int) (res *IPv6AddressSection) {
	res = NewIPv6SectionFromPrefixedRangeValues(vals, nil, segmentCount, nil)
	return
}

func NewIPv6SectionFromPrefixedValues(vals SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv6AddressSection) {
	return NewIPv6SectionFromPrefixedRangeValues(vals, nil, segmentCount, prefixLength)
}

func NewIPv6SectionFromRangeValues(vals, upperVals SegmentValueProvider, segmentCount int) (res *IPv6AddressSection) {
	res = NewIPv6SectionFromPrefixedRangeValues(vals, upperVals, segmentCount, nil)
	return
}

func NewIPv6SectionFromPrefixedRangeValues(vals, upperVals SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv6AddressSection) {
	if segmentCount < 0 {
		segmentCount = 0
	}
	segments, isMultiple := createSegments(
		vals, upperVals,
		segmentCount,
		IPv6BitsPerSegment,
		DefaultIPv6Network.getIPAddressCreator(),
		prefixLength)
	res = createIPv6Section(segments)
	res.isMultiple = isMultiple
	if prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIPAddressSection(), false, BitCount(segmentCount<<3))
	}
	return
}

func NewIPv6SectionFromMAC(eui *MACAddress) (res *IPv6AddressSection, err IncompatibleAddressError) {
	//segments := make([]*AddressDivision, 4)
	segments := createSegmentArray(4)
	if err = toIPv6SegmentsFromEUI(segments, 0, eui.GetSection(), nil); err != nil {
		return
	}
	res = createIPv6Section(segments)
	res.isMultiple = eui.IsMultiple()
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
		return section.GetPrefixCountLen(*section.GetPrefixLen())
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
	return section.maskPrefixed(other, false)
}

func (section *IPv6AddressSection) MaskPrefixed(other *IPv6AddressSection) (res *IPv6AddressSection, err IncompatibleAddressError) {
	return section.maskPrefixed(other, true)
}

func (section *IPv6AddressSection) maskPrefixed(other *IPv6AddressSection, retainPrefix bool) (res *IPv6AddressSection, err IncompatibleAddressError) {
	sec, err := section.mask(other.ToIPAddressSection(), retainPrefix)
	if err == nil {
		res = sec.ToIPv6AddressSection()
	}
	return
}

func (section *IPv6AddressSection) BitwiseOr(other *IPv6AddressSection) (res *IPv6AddressSection, err IncompatibleAddressError) {
	return section.bitwiseOrPrefixed(other, false)
}

func (section *IPv6AddressSection) BitwiseOrPrefixed(other *IPv6AddressSection) (res *IPv6AddressSection, err IncompatibleAddressError) {
	return section.bitwiseOrPrefixed(other, false)
}

func (section *IPv6AddressSection) bitwiseOrPrefixed(other *IPv6AddressSection, retainPrefix bool) (res *IPv6AddressSection, err IncompatibleAddressError) {
	sec, err := section.bitwiseOr(other.ToIPAddressSection(), retainPrefix)
	if err == nil {
		res = sec.ToIPv6AddressSection()
	}
	return
}

func (section *IPv6AddressSection) MatchesWithMask(other *IPv6AddressSection, mask *IPv6AddressSection) bool {
	return section.matchesWithMask(other.ToIPAddressSection(), mask.ToIPAddressSection())
}

func (section *IPv6AddressSection) Subtract(other *IPv6AddressSection) (res []*IPv6AddressSection, err SizeMismatchError) {
	sections, err := section.subtract(other.ToIPAddressSection())
	if err == nil {
		res = cloneIPSectsToIPv6Sects(sections)
	}
	return
}

func (section *IPv6AddressSection) Intersect(other *IPv6AddressSection) (res *IPv6AddressSection, err SizeMismatchError) {
	sec, err := section.intersect(other.ToIPAddressSection())
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
	res, err := section.toZeroHost(false)
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

func (section *IPv6AddressSection) AdjustPrefixLen(prefixLen BitCount) *IPv6AddressSection {
	return section.adjustPrefixLen(prefixLen).ToIPv6AddressSection()
}

func (section *IPv6AddressSection) AdjustPrefixLenZeroed(prefixLen BitCount) (*IPv6AddressSection, IncompatibleAddressError) {
	res, err := section.adjustPrefixLenZeroed(prefixLen)
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
	prefixLength := section.GetPrefixLen()
	result := fastIncrement(
		section.ToAddressSection(),
		increment,
		DefaultIPv6Network.getIPAddressCreator(),
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
		DefaultIPv6Network.getIPAddressCreator(),
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

//func (section *IPv6AddressSection) checkIndex(other *IPv6AddressSection) (err PositionMismatchError) {
//	if section.addressSegmentIndex != other.addressSegmentIndex {
//		err = &positionMismatchError{
//			section1:                 section.ToIPAddressSection(),
//			section2:                 other.ToIPAddressSection(),
//			addressSegmentIndex1:     section.addressSegmentIndex,
//			addressSegmentIndex2:     other.addressSegmentIndex,
//			incompatibleAddressError: incompatibleAddressError{addressError{key: "ipaddress.error.incompatible.position"}},
//		}
//	}
//	return
//}

func (section *IPv6AddressSection) SpanWithPrefixBlocksTo(other *IPv6AddressSection) ([]*IPv6AddressSection, IncompatibleAddressError) {
	//if err := section.checkIndex(other); err != nil {
	//	return nil, err
	//} else
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

func (section *IPv6AddressSection) SpanWithSequentialBlocksTo(other *IPv6AddressSection) ([]*IPv6AddressSection, IncompatibleAddressError) {
	//if err := section.checkIndex(other); err != nil {
	//	return nil, err
	//} else
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

func (section *IPv6AddressSection) CoverWithPrefixBlockTo(other *IPv6AddressSection) (*IPv6AddressSection, IncompatibleAddressError) {
	//if err := section.checkIndex(other); err != nil {
	//	return nil, err
	//}
	res, err := section.coverWithPrefixBlockTo(other.ToIPAddressSection())
	return res.ToIPv6AddressSection(), err
}

func (section *IPv6AddressSection) CoverWithPrefixBlock() *IPv6AddressSection {
	return section.coverWithPrefixBlock().ToIPv6AddressSection()
}

func (section *IPv6AddressSection) checkSectionCounts(sections []*IPv6AddressSection) IncompatibleAddressError {
	segCount := section.GetSegmentCount()
	//addressSegmentIndex := section.addressSegmentIndex
	length := len(sections)
	for i := 0; i < length; i++ {
		section2 := sections[i]
		if section2 == nil {
			continue
		}
		//if section2.addressSegmentIndex != addressSegmentIndex {
		//	return &positionMismatchError{
		//		section.ToIPAddressSection(),
		//		section2.ToIPAddressSection(),
		//		addressSegmentIndex,
		//		section.addressSegmentIndex,
		//		incompatibleAddressError{addressError{key: "ipaddress.error.incompatible.position"}}}
		//}
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
func (section *IPv6AddressSection) MergeToSequentialBlocks(sections ...*IPv6AddressSection) ([]*IPv6AddressSection, IncompatibleAddressError) {
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
func (section *IPv6AddressSection) MergeToPrefixBlocks(sections ...*IPv6AddressSection) ([]*IPv6AddressSection, IncompatibleAddressError) {
	if err := section.checkSectionCounts(sections); err != nil {
		return nil, err
	}
	series := cloneIPv6Sections(section, sections)
	blocks := getMergedPrefixBlocks(series)
	return cloneToIPv6Sections(blocks), nil
}

func (section *IPv6AddressSection) ReverseBits(perByte bool) (*IPv6AddressSection, IncompatibleAddressError) {
	res, err := section.reverseBits(perByte)
	return res.ToIPv6AddressSection(), err
}

func (section *IPv6AddressSection) ReverseBytes() (*IPv6AddressSection, IncompatibleAddressError) {
	res, err := section.reverseBytes(false)
	return res.ToIPv6AddressSection(), err
}

//func (section *IPv6AddressSection) ReverseBytesPerSegment() (*IPv6AddressSection, IncompatibleAddressError) {
//	res, err := section.reverseBytes(true)
//	return res.ToIPv6AddressSection(), err
//}

func (section *IPv6AddressSection) ReverseSegments() *IPv6AddressSection {
	if section.GetSegmentCount() <= 1 {
		if section.IsPrefixed() {
			return section.WithoutPrefixLen()
		}
		return section
	}
	res, _ := section.reverseSegments(
		func(i int) (*AddressSegment, IncompatibleAddressError) {
			return section.GetSegment(i).WithoutPrefixLen().ToAddressSegment(), nil
		},
	)
	return res.ToIPv6AddressSection()
}

func (section *IPv6AddressSection) Append(other *IPv6AddressSection) *IPv6AddressSection {
	count := section.GetSegmentCount()
	return section.ReplaceLen(count, count, other, 0, other.GetSegmentCount())
}

func (section *IPv6AddressSection) Insert(index int, other *IPv6AddressSection) *IPv6AddressSection {
	return section.insert(index, other.ToIPAddressSection(), ipv6BitsToSegmentBitshift).ToIPv6AddressSection()
}

// Replace the segments of this section starting at the given index with the given replacement segments
func (section *IPv6AddressSection) Replace(index int, replacement *IPv6AddressSection) *IPv6AddressSection {
	return section.ReplaceLen(index, index+replacement.GetSegmentCount(), replacement, 0, replacement.GetSegmentCount())
}

// Replaces segments starting from startIndex and ending before endIndex with the segments starting at replacementStartIndex and
//ending before replacementEndIndex from the replacement section
func (section *IPv6AddressSection) ReplaceLen(startIndex, endIndex int, replacement *IPv6AddressSection, replacementStartIndex, replacementEndIndex int) *IPv6AddressSection {
	return section.replaceLen(startIndex, endIndex, replacement.ToIPAddressSection(), replacementStartIndex, replacementEndIndex, ipv6BitsToSegmentBitshift).ToIPv6AddressSection()
}

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

	mixedParams         = NewIPv6StringOptionsBuilder().SetMixed(true).SetCompressOptions(compressMixed).ToOptions()
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

	ipv6ReverseDNSParams = NewIPv6StringOptionsBuilder().SetReverse(true).SetAddressSuffix(IPv6ReverseDnsSuffix).
				SetSplitDigits(true).SetExpandedSegments(true).SetSeparator('.').ToOptions()
	base85Params = new(IPStringOptionsBuilder).SetRadix(85).SetExpandedSegments(true).
			SetWildcards(base85Wildcards).SetZoneSeparator(IPv6AlternativeZoneSeparator).ToOptions()
	ipv6SegmentedBinaryParams = new(IPStringOptionsBuilder).SetRadix(2).SetSeparator(IPv6SegmentSeparator).SetSegmentStrPrefix(BinaryPrefix).
					SetExpandedSegments(true).ToOptions()
)

// ToCanonicalString produces a canonical string.
//
//If this section has a prefix length, it will be included in the string.
func (section *IPv6AddressSection) ToCanonicalString() string {
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
func (section *IPv6AddressSection) toMixedString() (string, IncompatibleAddressError) {
	cache := section.getStringCache()
	if cache == nil {
		return section.toMixedStringZoned(NoZone)
	}
	return cacheStrErr(&cache.mixedString,
		func() (string, IncompatibleAddressError) {
			return section.toMixedStringZoned(NoZone)
		})
}

func (section *IPv6AddressSection) ToNormalizedWildcardString() string {
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
	cache := section.getStringCache()
	if cache == nil {
		return section.toFullStringZoned(NoZone)
	}
	return cacheStr(&cache.fullString,
		func() string {
			return section.toFullStringZoned(NoZone)
		})
}

func (section *IPv6AddressSection) ToReverseDNSString() (string, IncompatibleAddressError) {
	cache := section.getStringCache()
	if cache == nil {
		return section.toReverseDNSStringZoned(NoZone)
	}
	return cacheStrErr(&cache.reverseDNSString,
		func() (string, IncompatibleAddressError) {
			return section.toReverseDNSStringZoned(NoZone)
		})
}

func (section *IPv6AddressSection) ToPrefixLenString() string {
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
	return section.ToPrefixLenString()
}

func (section *IPv6AddressSection) ToCompressedWildcardString() string {
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

func (section *IPv6AddressSection) toMixedStringZoned(zone Zone) (string, IncompatibleAddressError) {
	return section.toNormalizedMixedZonedString(mixedParams, zone)
}

func (section *IPv6AddressSection) toNormalizedWildcardStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(ipv6NormalizedWildcardParams, zone)
}

func (section *IPv6AddressSection) toCanonicalWildcardStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(canonicalWildcardParams, zone)
}

func (section *IPv6AddressSection) toSegmentedBinaryStringZoned(zone Zone) string {
	return section.ipAddressSectionInternal.toCustomString(ipv6SegmentedBinaryParams, zone)
}

func (section *IPv6AddressSection) toSQLWildcardStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(ipv6SqlWildcardParams, zone)
}

func (section *IPv6AddressSection) toFullStringZoned(zone Zone) string {
	return section.toNormalizedZonedString(ipv6FullParams, zone)
}

func (section *IPv6AddressSection) toReverseDNSStringZoned(zone Zone) (string, IncompatibleAddressError) {
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
func (section *IPv6AddressSection) ToCustomString(stringOptions IPv6StringOptions) (string, IncompatibleAddressError) {
	return section.toCustomString(stringOptions, NoZone)
}

func (section *IPv6AddressSection) toCustomString(stringOptions IPv6StringOptions, zone Zone) (string, IncompatibleAddressError) {
	if stringOptions.IsMixed() {
		return section.toNormalizedMixedZonedString(stringOptions, zone)
	} else if stringOptions.IsSplitDigits() {
		return section.toNormalizedSplitZonedString(stringOptions, zone)
	}
	return section.toNormalizedZonedString(stringOptions, zone), nil
}

func (section *IPv6AddressSection) toNormalizedZonedString(options IPv6StringOptions, zone Zone) string {
	var stringParams *ipv6StringParams
	if isCacheable(options) { // the isCacheable call is key and determines if the IPv6StringParams can be shared
		opts, hasCache := options.(*ipv6StringOptions)
		if hasCache {
			stringParams = opts.cachedIPv6Addr
		}
		if stringParams == nil {
			stringParams = from(options, section)
			if hasCache {
				dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&opts.cachedIPv6Addr))
				atomic.StorePointer(dataLoc, unsafe.Pointer(stringParams))
			}
		}
	} else {
		stringParams = from(options, section)
	}
	return stringParams.toZonedString(section, zone)
}

func (section *IPv6AddressSection) toNormalizedSplitZonedString(options IPv6StringOptions, zone Zone) (string, IncompatibleAddressError) {
	var stringParams *ipv6StringParams
	// all split strings are cacheable since no compression
	opts, hasCache := options.(*ipv6StringOptions)
	if hasCache {
		stringParams = opts.cachedIPv6Addr
	}
	if stringParams == nil {
		stringParams = from(options, section)
		if hasCache {
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&opts.cachedIPv6Addr))
			atomic.StorePointer(dataLoc, unsafe.Pointer(stringParams))
		}
	}
	return stringParams.toZonedSplitString(section, zone)
}

func (section *IPv6AddressSection) toNormalizedMixedZonedString(options IPv6StringOptions, zone Zone) (string, IncompatibleAddressError) {
	var stringParams *ipv6StringParams
	if isCacheable(options) { // the isCacheable call is key and determines if the IPv6StringParams can be shared (right not it just means not compressed)
		opts, hasCache := options.(*ipv6StringOptions)
		var mixedParams *ipv6v4MixedParams
		if hasCache {
			mixedParams = opts.cachedMixedIPv6Addr
		}
		if mixedParams == nil {
			stringParams = from(options, section)
			mixedParams := &ipv6v4MixedParams{
				ipv6Params: stringParams,
				ipv4Params: toIPParams(options.GetIPv4Opts()),
			}
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&opts.cachedMixedIPv6Addr))
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

func (section *IPv6AddressSection) toNormalizedMixedString(mixedParams *ipv6v4MixedParams, zone Zone) (string, IncompatibleAddressError) {
	mixed, err := section.getMixedAddressGrouping()
	if err != nil {
		return "", err
	}
	result := mixedParams.toZonedString(mixed, zone)
	return result, nil
}

func (section *IPv6AddressSection) ToIPAddressSection() *IPAddressSection {
	return (*IPAddressSection)(unsafe.Pointer(section))
}

func (section *IPv6AddressSection) getMixedAddressGrouping() (*IPv6v4MixedAddressGrouping, IncompatibleAddressError) {
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
func (section *IPv6AddressSection) getEmbeddedIPv4AddressSection() (*IPv4AddressSection, IncompatibleAddressError) {
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
func (section *IPv6AddressSection) GetIPv4AddressSection(startIndex, endIndex int) (*IPv4AddressSection, IncompatibleAddressError) {
	//addressSegmentIndex := section.addressSegmentIndex
	//if startIndex == (IPv6MixedOriginalSegmentCount-int(addressSegmentIndex))<<1 && endIndex == (section.GetSegmentCount()<<1) {
	//	return section.getEmbeddedIPv4AddressSection()
	//}
	if startIndex == IPv6MixedOriginalSegmentCount<<1 && endIndex == (section.GetSegmentCount()<<1) {
		return section.getEmbeddedIPv4AddressSection()
	}
	segments := make([]*AddressDivision, endIndex-startIndex)
	i := startIndex
	j := 0
	bytesPerSegment := section.GetBytesPerSegment()
	if i%bytesPerSegment == 1 {
		ipv6Segment := section.GetSegment(i >> 1)
		i++
		if err := ipv6Segment.SplitIntoIPv4Segments(segments, j-1); err != nil {
			return nil, err
		}
		j++
	}
	for ; i < endIndex; i, j = i+bytesPerSegment, j+bytesPerSegment {
		ipv6Segment := section.GetSegment(i >> 1)
		if err := ipv6Segment.SplitIntoIPv4Segments(segments, j); err != nil {
			return nil, err
		}
	}
	res := createIPv4Section(segments)
	_ = res.initMultAndPrefLen()
	return res, nil
}

func (section *IPv6AddressSection) createNonMixedSection() *IPv6AddressSection {
	nonMixedCount := IPv6MixedOriginalSegmentCount
	//nonMixedCount := 0
	//addressSegmentIndex := section.addressSegmentIndex
	//if count := IPv6MixedOriginalSegmentCount - int(addressSegmentIndex); count > 0 {
	//	nonMixedCount = count
	//}
	//if count := IPv6MixedOriginalSegmentCount; count > 0 {
	//	nonMixedCount = count
	//}
	mixedCount := section.GetSegmentCount() - nonMixedCount
	if mixedCount <= 0 {
		return section
	}
	nonMixed := make([]*AddressDivision, nonMixedCount)
	section.copySubSegmentsToSlice(0, nonMixedCount, nonMixed)
	res := createIPv6Section(nonMixed)
	_ = res.initMultAndPrefLen()
	return res
}

func (section *IPv6AddressSection) createEmbeddedIPv4AddressSection() (sect *IPv4AddressSection, err IncompatibleAddressError) {
	nonMixedCount := IPv6MixedOriginalSegmentCount
	//nonMixedCount := 0
	//addressSegmentIndex := section.addressSegmentIndex
	//if count := IPv6MixedOriginalSegmentCount - int(addressSegmentIndex); count > 0 {
	//	nonMixedCount = count
	//}
	segCount := section.GetSegmentCount()
	mixedCount := segCount - nonMixedCount
	lastIndex := segCount - 1
	var mixed []*AddressDivision
	if mixedCount == 0 {
		mixed = []*AddressDivision{}
	} else if mixedCount == 1 {
		mixed = make([]*AddressDivision, section.GetBytesPerSegment())
		last := section.GetSegment(lastIndex)
		if err := last.SplitIntoIPv4Segments(mixed, 0); err != nil {
			return nil, err
		}
	} else {
		bytesPerSeg := section.GetBytesPerSegment()
		mixed = make([]*AddressDivision, bytesPerSeg<<1)
		low := section.GetSegment(lastIndex)
		high := section.GetSegment(lastIndex - 1)
		if err := high.SplitIntoIPv4Segments(mixed, 0); err != nil {
			return nil, err
		}
		if err := low.SplitIntoIPv4Segments(mixed, bytesPerSeg); err != nil {
			return nil, err
		}
	}
	sect = createIPv4Section(mixed)
	_ = sect.initMultAndPrefLen()
	return
}

func createMixedAddressSection(divisions []*AddressDivision) *IPv6v4MixedAddressGrouping {
	return &IPv6v4MixedAddressGrouping{
		addressDivisionGroupingInternal: addressDivisionGroupingInternal{
			addressDivisionGroupingBase: addressDivisionGroupingBase{
				divisions: standardDivArray{divisions},
				addrType:  ipv6v4MixedType,
				cache:     &valueCache{},
			},
		},
	}
}

func newIPv6v4MixedGrouping(ipv6Section *IPv6AddressSection, ipv4Section *IPv4AddressSection) *IPv6v4MixedAddressGrouping {
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
	section.cache.mixed = &mixedCache{
		embeddedIPv6Section: ipv6Section,
		embeddedIPv4Section: ipv4Section,
	}
	section.isMultiple = ipv6Section.IsMultiple() || ipv4Section.IsMultiple()
	if ipv6Section.IsPrefixed() {
		section.prefixLength = ipv6Section.GetPrefixLen()
	} else if ipv4Section.IsPrefixed() {
		section.prefixLength = cacheBitCount(ipv6Section.GetBitCount() + *ipv4Section.GetPrefixLen())
	}
	return section
}

type IPv6v4MixedAddressGrouping struct {
	addressDivisionGroupingInternal
}

func (grouping *IPv6v4MixedAddressGrouping) ToAddressDivisionGrouping() *AddressDivisionGrouping {
	return (*AddressDivisionGrouping)(grouping)
}

func (grouping *IPv6v4MixedAddressGrouping) GetIPv6AddressSection() *IPv6AddressSection {
	cache := grouping.cache
	if cache == nil {
		subDivs := grouping.getSubDivisions(0, IPv6MixedOriginalSegmentCount)
		return newIPv6SectionParsed(subDivs)
	}
	return cache.mixed.embeddedIPv6Section
}

func (grouping *IPv6v4MixedAddressGrouping) GetIPv4AddressSection() *IPv4AddressSection {
	cache := grouping.cache
	if cache == nil {
		subDivs := grouping.getSubDivisions(IPv6MixedOriginalSegmentCount, grouping.GetDivisionCount())
		return newIPv4SectionParsed(subDivs)
	}
	return cache.mixed.embeddedIPv4Section
}

//func (sect *IPv6v4MixedAddressGrouping) GetGenericIPDivision(index int) IPAddressGenericDivision {
//	ipv6Section := sect.ipv6Section
//	if index < ipv6Section.GetSegmentCount() {
//		return ipv6Section.GetSegment(index)
//	}
//	return sect.ipv4Section.GetSegment(index)
//}

var ffMACSeg, feMACSeg = NewMACSegment(0xff), NewMACSegment(0xfe)

func toIPv6SegmentsFromEUI(
	segments []*AddressDivision,
	ipv6StartIndex int, // the index into the IPv6 segment array to put the MAC-based IPv6 segments
	eui *MACAddressSection, // must be full 6 or 8 mac sections
	prefixLength PrefixLen) IncompatibleAddressError {
	euiSegmentIndex := 0
	var seg3, seg4 *MACAddressSegment
	var err IncompatibleAddressError
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
		//since the prefix comes from the ipv6 section and not the MAC section, any segment prefix for the MAC section is 0 or null
		//prefixes across segments have the pattern: null, null, ..., null, 0-16, 0, 0, ..., 0
		//So if the overall prefix is 0, then the prefix of every segment is 0
		currentPrefix = cacheBitCount(0)
	}
	var seg *IPv6AddressSegment
	if seg, err = seg0.JoinAndFlip2ndBit(seg1, currentPrefix); /* only this first one gets the flipped bit */ err == nil {
		segments[ipv6StartIndex] = seg.ToAddressDivision()
		ipv6StartIndex++
		if seg, err = seg2.Join(seg3, currentPrefix); err == nil {
			segments[ipv6StartIndex] = seg.ToAddressDivision()
			ipv6StartIndex++
			if seg, err = seg4.Join(seg5, currentPrefix); err == nil {
				segments[ipv6StartIndex] = seg.ToAddressDivision()
				ipv6StartIndex++
				if seg, err = seg6.Join(seg7, currentPrefix); err == nil {
					segments[ipv6StartIndex] = seg.ToAddressDivision()
					return nil
				}
			}
		}
	}
	return err
}

//func joinMacSegs(macSegment0, macSegment1 *MACAddressSegment, prefixLength PrefixLen) (*IPv6AddressSegment, IncompatibleAddressError) {
//	return joinMacSegsFlip(macSegment0, macSegment1, false, prefixLength)
//}
//
//func joinMacSegsFlip(macSegment0, macSegment1 *MACAddressSegment, flip bool, prefixLength PrefixLen) (*IPv6AddressSegment, IncompatibleAddressError) {
//	if macSegment0.isMultiple() {
//		// if the high segment has a range, the low segment must match the full range,
//		// otherwise it is not possible to create an equivalent range when joining
//		if !macSegment1.IsFullRange() {
//			return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.invalidMACIPv6Range"}}
//		}
//	}
//	lower0 := macSegment0.GetSegmentValue()
//	upper0 := macSegment0.GetUpperSegmentValue()
//	if flip {
//		mask2ndBit := SegInt(0x2)
//		if !macSegment0.MatchesWithMask(mask2ndBit&lower0, mask2ndBit) {
//			return nil, &incompatibleAddressError{addressError{key: "ipaddress.mac.error.not.eui.convertible"}}
//		}
//		lower0 ^= mask2ndBit //flip the universal/local bit
//		upper0 ^= mask2ndBit
//	}
//	return NewIPv6RangePrefixedSegment(
//		IPv6SegInt((lower0<<8)|macSegment1.getSegmentValue()),
//		IPv6SegInt((upper0<<8)|macSegment1.getUpperSegmentValue()),
//		prefixLength), nil
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
