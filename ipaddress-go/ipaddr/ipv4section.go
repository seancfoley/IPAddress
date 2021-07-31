package ipaddr

import (
	"math/big"
	"sync/atomic"
	"unsafe"
)

func createIPv4Section(segments []*AddressDivision) *IPv4AddressSection {
	return &IPv4AddressSection{
		ipAddressSectionInternal{
			addressSectionInternal{
				addressDivisionGroupingInternal{
					addressDivisionGroupingBase: addressDivisionGroupingBase{
						divisions: standardDivArray{segments},
						addrType:  ipv4Type,
						cache: &valueCache{
							stringCache: stringCache{
								ipStringCache:   &ipStringCache{},
								ipv4StringCache: &ipv4StringCache{},
							},
						},
					},
				},
			},
		},
	}
}

// error returned for invalid segment count, nil sements, segments with invalid bit size, or inconsistent prefixes
func newIPv4AddressSection(segments []*AddressDivision /*cloneSegments bool,*/, normalizeSegments bool) (res *IPv4AddressSection, err AddressValueError) {
	segsLen := len(segments)
	if segsLen > IPv4SegmentCount {
		err = &addressValueError{val: segsLen, addressError: addressError{key: "ipaddress.error.exceeds.size"}}
		return
	}
	res = createIPv4Section(segments)
	if err = res.initMultAndPrefLen(); err != nil {
		res = nil
		return
	}
	prefLen := res.prefixLength
	if normalizeSegments && prefLen != nil {
		normalizePrefixBoundary(*prefLen, segments, IPv4BitsPerSegment, IPv4BytesPerSegment, func(val, upperVal SegInt, prefLen PrefixLen) *AddressDivision {
			return NewIPv4RangePrefixSegment(IPv4SegInt(val), IPv4SegInt(upperVal), prefLen).ToAddressDivision()
		})
	}
	return
}

func newIPv4AddressSectionParsed(segments []*AddressDivision) (res *IPv4AddressSection) {
	res = createIPv4Section(segments)
	_ = res.initMultAndPrefLen()
	return
}

//TODO need the public equivalent of this constructor that takes []*IPv4AddressSegment (and not []*AddressDivision)

func newIPv4AddressSectionSingle(segments []*AddressDivision, prefixLength PrefixLen, singleOnly bool) (res *IPv4AddressSection, err AddressValueError) {
	res, err = newIPv4AddressSection(segments /*cloneSegments,*/, prefixLength == nil)
	if err == nil && prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIPAddressSection(), singleOnly, BitCount(len(segments)<<3))
	}
	return
}

func NewIPv4AddressSectionFromBytes(bytes []byte) (res *IPv4AddressSection, err AddressValueError) {
	return newIPv4AddressSectionFromBytes(bytes, len(bytes), nil, false)
}

// Useful if the byte array has leading zeros or leading sign extension
func NewIPv4AddressSectionFromSegmentedBytes(bytes []byte, segmentCount int) (res *IPv4AddressSection, err AddressValueError) {
	return newIPv4AddressSectionFromBytes(bytes, segmentCount, nil, false)
}

func NewIPv4AddressSectionFromPrefixedBytes(bytes []byte, segmentCount int, prefixLength PrefixLen) (res *IPv4AddressSection, err AddressValueError) {
	return newIPv4AddressSectionFromBytes(bytes, segmentCount, prefixLength, false)
}

func newIPv4AddressSectionFromBytes(bytes []byte, segmentCount int, prefixLength PrefixLen, singleOnly bool) (res *IPv4AddressSection, err AddressValueError) {
	if segmentCount < 0 {
		segmentCount = len(bytes)
	}
	expectedByteCount := segmentCount
	segments, err := toSegments(
		bytes,
		segmentCount,
		IPv4BytesPerSegment,
		IPv4BitsPerSegment,
		expectedByteCount,
		DefaultIPv4Network.getIPAddressCreator(),
		prefixLength)
	if err == nil {
		res = createIPv4Section(segments)
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

func NewIPv4AddressSectionFromVals(vals SegmentValueProvider, segmentCount int) (res *IPv4AddressSection) {
	res = NewIPv4AddressSectionFromPrefixedRangeVals(vals, nil, segmentCount, nil)
	return
}

func NewIPv4AddressSectionFromPrefixedVals(vals SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv4AddressSection) {
	return NewIPv4AddressSectionFromPrefixedRangeVals(vals, nil, segmentCount, prefixLength)
}

func NewIPv4AddressSectionFromRangeVals(vals, upperVals SegmentValueProvider, segmentCount int) (res *IPv4AddressSection) {
	res = NewIPv4AddressSectionFromPrefixedRangeVals(vals, upperVals, segmentCount, nil)
	return
}

func NewIPv4AddressSectionFromPrefixedRangeVals(vals, upperVals SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv4AddressSection) {
	if segmentCount < 0 {
		segmentCount = 0
	}
	segments, isMultiple := createSegments(
		vals, upperVals,
		segmentCount,
		IPv4BitsPerSegment,
		DefaultIPv4Network.getIPAddressCreator(),
		prefixLength)
	res = createIPv4Section(segments)
	res.isMultiple = isMultiple
	if prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIPAddressSection(), false, BitCount(segmentCount<<3))
	}
	return
}

// IPv4AddressSection represents a section of an IPv4 address comprising 0 to 4 IPv4 address segments.
// The zero values is a section with zero segments.
type IPv4AddressSection struct {
	ipAddressSectionInternal
}

func (section *IPv4AddressSection) GetBitsPerSegment() BitCount {
	return IPv4BitsPerSegment
}

func (section *IPv4AddressSection) GetBytesPerSegment() int {
	return IPv4BytesPerSegment
}

func (section *IPv4AddressSection) GetIPVersion() IPVersion {
	return IPv4
}

func (section *IPv4AddressSection) GetCount() *big.Int {
	return section.cacheCount(func() *big.Int {
		return bigZero().SetUint64(section.GetIPv4Count())
	})
}

func (section *IPv4AddressSection) GetPrefixCount() *big.Int {
	return section.cachePrefixCount(func() *big.Int {
		return bigZero().SetUint64(section.GetIPv4PrefixCount())
	})
}

func (section *IPv4AddressSection) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	if prefixLen <= 0 {
		return bigOne()
	} else if bc := section.GetBitCount(); prefixLen > bc {
		prefixLen = bc
	}
	return section.calcCount(func() *big.Int { return new(big.Int).SetUint64(section.GetIPv4PrefixCountLen(prefixLen)) })
}

// GetIPv4PrefixCountLen gives count available as a uint64 instead of big.Int
func (section *IPv4AddressSection) GetIPv4PrefixCountLen(prefixLength BitCount) uint64 {
	if !section.IsMultiple() {
		return 1
	} else if prefixLength >= section.GetBitCount() {
		return section.GetIPv4Count()
	}
	return longPrefixCount(section.ToAddressSection(), prefixLength)
}

func (section *IPv4AddressSection) GetIPv4PrefixCount() uint64 {
	prefixLength := section.GetPrefixLength()
	if prefixLength == nil {
		return section.GetIPv4Count()
	}
	return section.GetIPv4PrefixCountLen(*prefixLength)
}

func (section *IPv4AddressSection) GetIPv4Count() uint64 {
	if !section.IsMultiple() {
		return 1
	}
	return longCount(section.ToAddressSection(), section.GetSegmentCount())
}

func (section *IPv4AddressSection) GetSegment(index int) *IPv4AddressSegment {
	return section.getDivision(index).ToIPv4AddressSegment()
}

// Gets the subsection from the series starting from the given index
// The first segment is at index 0.
func (section *IPv4AddressSection) GetTrailingSection(index int) *IPv4AddressSection {
	return section.GetSubSection(index, section.GetSegmentCount())
}

//// Gets the subsection from the series starting from the given index and ending just before the give endIndex
//// The first segment is at index 0.
func (section *IPv4AddressSection) GetSubSection(index, endIndex int) *IPv4AddressSection {
	return section.getSubSection(index, endIndex).ToIPv4AddressSection()
}

func (section *IPv4AddressSection) GetNetworkSection() *IPv4AddressSection {
	return section.getNetworkSection().ToIPv4AddressSection()
}

func (section *IPv4AddressSection) GetNetworkSectionLen(prefLen BitCount) *IPv4AddressSection {
	return section.getNetworkSectionLen(prefLen).ToIPv4AddressSection()
}

func (section *IPv4AddressSection) GetHostSection() *IPv4AddressSection {
	return section.getHostSection().ToIPv4AddressSection()
}

func (section *IPv4AddressSection) GetHostSectionLen(prefLen BitCount) *IPv4AddressSection {
	return section.getHostSectionLen(prefLen).ToIPv4AddressSection()
}

func (section *IPv4AddressSection) GetNetworkMask() *IPv4AddressSection {
	return section.getNetworkMask(DefaultIPv4Network).ToIPv4AddressSection()
}

func (section *IPv4AddressSection) GetHostMask() *IPv4AddressSection {
	return section.getHostMask(DefaultIPv4Network).ToIPv4AddressSection()
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *IPv4AddressSection) CopySubSegments(start, end int, segs []*IPv4AddressSegment) (count int) {
	return section.visitSubSegments(start, end, func(index int, div *AddressDivision) bool { segs[index] = div.ToIPv4AddressSegment(); return false }, len(segs))
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *IPv4AddressSection) CopySegments(segs []*IPv4AddressSegment) (count int) {
	return section.visitSegments(func(index int, div *AddressDivision) bool { segs[index] = div.ToIPv4AddressSegment(); return false }, len(segs))
}

// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this section.
func (section *IPv4AddressSection) GetSegments() (res []*IPv4AddressSegment) {
	res = make([]*IPv4AddressSegment, section.GetSegmentCount())
	section.CopySegments(res)
	return
}

func (section *IPv4AddressSection) Mask(other *IPv4AddressSection) (res *IPv4AddressSection, err IncompatibleAddressError) {
	return section.maskPrefixed(other, false)
}

func (section *IPv4AddressSection) MaskPrefixed(other *IPv4AddressSection) (res *IPv4AddressSection, err IncompatibleAddressError) {
	return section.maskPrefixed(other, true)
}

func (section *IPv4AddressSection) maskPrefixed(other *IPv4AddressSection, retainPrefix bool) (res *IPv4AddressSection, err IncompatibleAddressError) {
	sec, err := section.mask(other.ToIPAddressSection(), retainPrefix)
	if err == nil {
		res = sec.ToIPv4AddressSection()
	}
	return
}

func (section *IPv4AddressSection) BitwiseOr(other *IPv4AddressSection) (res *IPv4AddressSection, err IncompatibleAddressError) {
	return section.bitwiseOrPrefixed(other, false)
}

func (section *IPv4AddressSection) BitwiseOrPrefixed(other *IPv4AddressSection) (res *IPv4AddressSection, err IncompatibleAddressError) {
	return section.bitwiseOrPrefixed(other, true)
}

func (section *IPv4AddressSection) bitwiseOrPrefixed(other *IPv4AddressSection, retainPrefix bool) (res *IPv4AddressSection, err IncompatibleAddressError) {
	sec, err := section.bitwiseOr(other.ToIPAddressSection(), retainPrefix)
	if err == nil {
		res = sec.ToIPv4AddressSection()
	}
	return
}

func (section *IPv4AddressSection) Subtract(other *IPv4AddressSection) (res []*IPv4AddressSection, err SizeMismatchError) {
	sections, err := section.subtract(other.ToIPAddressSection())
	if err == nil {
		res = cloneIPSectsToIPv4Sects(sections)
	}
	return
}

func (section *IPv4AddressSection) Intersect(other *IPv4AddressSection) (res *IPv4AddressSection, err SizeMismatchError) {
	sec, err := section.intersect(other.ToIPAddressSection())
	if err == nil {
		res = sec.ToIPv4AddressSection()
	}
	return
}

func (section *IPv4AddressSection) GetLower() *IPv4AddressSection {
	return section.getLower().ToIPv4AddressSection()
}

func (section *IPv4AddressSection) GetUpper() *IPv4AddressSection {
	return section.getUpper().ToIPv4AddressSection()
}

func (section *IPv4AddressSection) ToZeroHost() (*IPv4AddressSection, IncompatibleAddressError) {
	res, err := section.toZeroHost(false)
	return res.ToIPv4AddressSection(), err
}

func (section *IPv4AddressSection) ToZeroHostLen(prefixLength BitCount) (*IPv4AddressSection, IncompatibleAddressError) {
	res, err := section.toZeroHostLen(prefixLength)
	return res.ToIPv4AddressSection(), err
}

func (section *IPv4AddressSection) ToZeroNetwork() *IPv4AddressSection {
	return section.toZeroNetwork().ToIPv4AddressSection()
}

func (section *IPv4AddressSection) ToMaxHost() (*IPv4AddressSection, IncompatibleAddressError) {
	res, err := section.toMaxHost()
	return res.ToIPv4AddressSection(), err
}

func (section *IPv4AddressSection) ToMaxHostLen(prefixLength BitCount) (*IPv4AddressSection, IncompatibleAddressError) {
	res, err := section.toMaxHostLen(prefixLength)
	return res.ToIPv4AddressSection(), err
}

//func (section *IPv4AddressSection) Uint64Value() uint64 {
//	return uint64(section.Uint32Value())
//}
//
//func (section *IPv4AddressSection) UpperUint64Value() uint64 {
//	return uint64(section.UpperUint32Value())
//}

func (section *IPv4AddressSection) Uint32Value() uint32 {
	lower, _ := section.getIntValues()
	return lower
}

func (section *IPv4AddressSection) UpperUint32Value() uint32 {
	_, upper := section.getIntValues()
	return upper
}

func (section *IPv4AddressSection) getIntValues() (lower, upper uint32) {
	segCount := section.GetSegmentCount()
	if segCount == 0 {
		return 0, 0
	}
	cache := section.cache
	cached := cache.intsCache
	if cached == nil {
		cached = &intsCache{}
		cached.cachedLowerVal, cached.cachedUpperVal = section.calcIntValues()
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.intsCache))
		atomic.StorePointer(dataLoc, unsafe.Pointer(cached))
	}
	lower = cached.cachedLowerVal
	upper = cached.cachedUpperVal
	return
}

func (section *IPv4AddressSection) calcIntValues() (lower, upper uint32) {
	segCount := section.GetSegmentCount()
	isMult := section.IsMultiple()
	if segCount == 4 {
		lower = (uint32(section.GetSegment(0).GetSegmentValue()) << 24) |
			(uint32(section.GetSegment(1).GetSegmentValue()) << 16) |
			(uint32(section.GetSegment(2).GetSegmentValue()) << 8) |
			uint32(section.GetSegment(3).GetSegmentValue())
		if isMult {
			upper = (uint32(section.GetSegment(0).GetUpperSegmentValue()) << 24) |
				(uint32(section.GetSegment(1).GetUpperSegmentValue()) << 16) |
				(uint32(section.GetSegment(2).GetUpperSegmentValue()) << 8) |
				uint32(section.GetSegment(3).GetUpperSegmentValue())
		} else {
			upper = lower
		}
		return
	}
	seg := section.GetSegment(0)
	lower = uint32(seg.GetSegmentValue())
	if isMult {
		upper = uint32(seg.GetUpperSegmentValue())
	}
	bitsPerSegment := section.GetBitsPerSegment()
	for i := 1; i < segCount; i++ {
		seg = section.GetSegment(i)
		lower = (lower << uint(bitsPerSegment)) | uint32(seg.GetSegmentValue())
		if isMult {
			upper = (upper << uint(bitsPerSegment)) | uint32(seg.GetUpperSegmentValue())
		}
	}
	if !isMult {
		upper = lower
	}
	return
}

//func (section *IPv4AddressSection) getIntValue(lower bool) (result uint32) {
//	segCount := section.GetSegmentCount() xxx
//	if segCount == 0 {
//		return 0
//	}
//	cacheBitCountx := section.cacheBitCountx
//	var val *uint32
//	if lower {
//		val = cacheBitCountx.cachedLowerVal
//	} else {
//		val = cacheBitCountx.cachedUpperVal
//	}
//	if val != nil {
//		return *val
//	}
//	if segCount == 4 {
//		if lower {
//			result = (uint32(section.GetSegment(0).GetSegmentValue()) << 24) |
//				(uint32(section.GetSegment(1).GetSegmentValue()) << 16) |
//				(uint32(section.GetSegment(2).GetSegmentValue()) << 8) |
//				uint32(section.GetSegment(3).GetSegmentValue())
//		} else {
//			result = (uint32(section.GetSegment(0).GetUpperSegmentValue()) << 24) |
//				(uint32(section.GetSegment(1).GetUpperSegmentValue()) << 16) |
//				(uint32(section.GetSegment(2).GetUpperSegmentValue()) << 8) |
//				uint32(section.GetSegment(3).GetUpperSegmentValue())
//		}
//	} else {
//		seg := section.GetSegment(0)
//		if lower {
//			result = uint32(seg.GetSegmentValue())
//		} else {
//			result = uint32(seg.GetUpperSegmentValue())
//		}
//		bitsPerSegment := section.GetBitsPerSegment()
//		for i := 1; i < segCount; i++ {
//			result = (result << bitsPerSegment)
//			seg = section.GetSegment(i)
//			if lower {
//				result |= uint32(seg.GetSegmentValue())
//			} else {
//				result |= uint32(seg.GetUpperSegmentValue())
//			}
//		}
//	}
//	var dataLoc *unsafe.Pointer
//	if lower {
//		dataLoc = (*unsafe.Pointer)(unsafe.Pointer(&cacheBitCountx.cachedLowerVal))
//	} else {
//		dataLoc = (*unsafe.Pointer)(unsafe.Pointer(&cacheBitCountx.cachedUpperVal))
//	}
//	atomic.StorePointer(dataLoc, unsafe.Pointer(&result))
//	return result
//}

func (section *IPv4AddressSection) ToPrefixBlock() *IPv4AddressSection {
	return section.toPrefixBlock().ToIPv4AddressSection()
}

func (section *IPv4AddressSection) ToPrefixBlockLen(prefLen BitCount) *IPv4AddressSection {
	return section.toPrefixBlockLen(prefLen).ToIPv4AddressSection()
}

func (section *IPv4AddressSection) ToBlock(segmentIndex int, lower, upper SegInt) *IPv4AddressSection {
	return section.toBlock(segmentIndex, lower, upper).ToIPv4AddressSection()
}

func (section *IPv4AddressSection) WithoutPrefixLen() *IPv4AddressSection {
	return section.withoutPrefixLen().ToIPv4AddressSection()
}

func (section *IPv4AddressSection) SetPrefixLen(prefixLen BitCount) *IPv4AddressSection {
	return section.setPrefixLen(prefixLen).ToIPv4AddressSection()
}

func (section *IPv4AddressSection) SetPrefixLenZeroed(prefixLen BitCount) (*IPv4AddressSection, IncompatibleAddressError) {
	res, err := section.setPrefixLenZeroed(prefixLen)
	return res.ToIPv4AddressSection(), err
}

func (section *IPv4AddressSection) AdjustPrefixLen(prefixLen BitCount) *IPv4AddressSection {
	return section.adjustPrefixLen(prefixLen).ToIPv4AddressSection()
}

func (section *IPv4AddressSection) AdjustPrefixLenZeroed(prefixLen BitCount) (*IPv4AddressSection, IncompatibleAddressError) {
	res, err := section.adjustPrefixLenZeroed(prefixLen)
	return res.ToIPv4AddressSection(), err
}

func (section *IPv4AddressSection) AssignPrefixForSingleBlock() *IPv4AddressSection {
	return section.assignPrefixForSingleBlock().ToIPv4AddressSection()
}

func (section *IPv4AddressSection) AssignMinPrefixForBlock() *IPv4AddressSection {
	return section.assignMinPrefixForBlock().ToIPv4AddressSection()
}

func (section *IPv4AddressSection) Iterator() IPv4SectionIterator {
	return ipv4SectionIterator{section.sectionIterator(nil)}
}

func (section *IPv4AddressSection) PrefixIterator() IPv4SectionIterator {
	return ipv4SectionIterator{section.prefixIterator(false)}
}

func (section *IPv4AddressSection) PrefixBlockIterator() IPv4SectionIterator {
	return ipv4SectionIterator{section.prefixIterator(true)}
}

func (section *IPv4AddressSection) BlockIterator(segmentCount int) IPv4SectionIterator {
	return ipv4SectionIterator{section.blockIterator(segmentCount)}
}

func (section *IPv4AddressSection) SequentialBlockIterator() IPv4SectionIterator {
	return ipv4SectionIterator{section.sequentialBlockIterator()}
}

func (section *IPv4AddressSection) ToIPAddressSection() *IPAddressSection {
	return (*IPAddressSection)(unsafe.Pointer(section))
}

func (section *IPv4AddressSection) IncrementBoundary(increment int64) *IPv4AddressSection {
	return section.incrementBoundary(increment).ToIPv4AddressSection()
}

func getIPv4MaxValueLong(segmentCount int) uint64 {
	return macMaxValues[segmentCount]
}

func (section *IPv4AddressSection) Increment(inc int64) *IPv4AddressSection {
	if inc == 0 && !section.IsMultiple() {
		return section
	}
	lowerValue := uint64(section.Uint32Value())
	upperValue := uint64(section.UpperUint32Value())
	count := section.GetIPv4Count()
	isOverflow := checkOverflow(inc, lowerValue, upperValue, count, getIPv4MaxValueLong(section.GetSegmentCount()))
	if isOverflow {
		return nil
	}
	return increment(
		section.ToAddressSection(),
		inc,
		DefaultIPv4Network.getIPAddressCreator(),
		count,
		lowerValue,
		upperValue,
		section.getLower,
		section.getUpper,
		section.GetPrefixLength()).ToIPv4AddressSection()
}

func (section *IPv4AddressSection) SpanWithPrefixBlocks() []*IPv4AddressSection {
	if section.IsSequential() {
		if section.IsSinglePrefixBlock() {
			return []*IPv4AddressSection{section}
		}
		wrapped := WrappedIPAddressSection{section.ToIPAddressSection()}
		spanning := getSpanningPrefixBlocks(wrapped, wrapped)
		return cloneToIPv4Sections(spanning)
	}
	wrapped := WrappedIPAddressSection{section.ToIPAddressSection()}
	return cloneToIPv4Sections(spanWithPrefixBlocks(wrapped))
}

func (section *IPv4AddressSection) SpanWithPrefixBlocksTo(other *IPv4AddressSection) ([]*IPv4AddressSection, SizeMismatchError) {
	if err := section.checkSectionCount(other.ToIPAddressSection()); err != nil {
		return nil, err
	}
	return cloneToIPv4Sections(
		getSpanningPrefixBlocks(
			WrappedIPAddressSection{section.ToIPAddressSection()},
			WrappedIPAddressSection{other.ToIPAddressSection()},
		),
	), nil
}

func (section *IPv4AddressSection) SpanWithSequentialBlocks() []*IPv4AddressSection {
	if section.IsSequential() {
		return []*IPv4AddressSection{section}
	}
	wrapped := WrappedIPAddressSection{section.ToIPAddressSection()}
	return cloneToIPv4Sections(spanWithSequentialBlocks(wrapped))
}

func (section *IPv4AddressSection) SpanWithSequentialBlocksTo(other *IPv4AddressSection) ([]*IPv4AddressSection, SizeMismatchError) {
	if err := section.checkSectionCount(other.ToIPAddressSection()); err != nil {
		return nil, err
	}
	return cloneToIPv4Sections(
		getSpanningSequentialBlocks(
			WrappedIPAddressSection{section.ToIPAddressSection()},
			WrappedIPAddressSection{other.ToIPAddressSection()},
		),
	), nil
}

func (section *IPv4AddressSection) CoverWithPrefixBlockTo(other *IPv4AddressSection) (*IPv4AddressSection, SizeMismatchError) {
	res, err := section.coverWithPrefixBlockTo(other.ToIPAddressSection())
	return res.ToIPv4AddressSection(), err
}

func (section *IPv4AddressSection) CoverWithPrefixBlock() *IPv4AddressSection {
	return section.coverWithPrefixBlock().ToIPv4AddressSection()
}

func (section *IPv4AddressSection) checkSectionCounts(sections []*IPv4AddressSection) SizeMismatchError {
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
func (section *IPv4AddressSection) MergeToSequentialBlocks(sections ...*IPv4AddressSection) ([]*IPv4AddressSection, IncompatibleAddressError) {
	if err := section.checkSectionCounts(sections); err != nil {
		return nil, err
	}
	series := cloneIPv4Sections(section, sections)
	blocks := getMergedSequentialBlocks(series)
	return cloneToIPv4Sections(blocks), nil
}

//
// MergeToPrefixBlocks merges this with the list of sections to produce the smallest array of prefix blocks.
//
// The resulting array is sorted from lowest address value to highest, regardless of the size of each prefix block.
func (section *IPv4AddressSection) MergeToPrefixBlocks(sections ...*IPv4AddressSection) ([]*IPv4AddressSection, IncompatibleAddressError) {
	if err := section.checkSectionCounts(sections); err != nil {
		return nil, err
	}
	series := cloneIPv4Sections(section, sections)
	blocks := getMergedPrefixBlocks(series)
	return cloneToIPv4Sections(blocks), nil
}

func (section *IPv4AddressSection) ReverseBits(perByte bool) (*IPv4AddressSection, IncompatibleAddressError) {
	res, err := section.reverseBits(perByte)
	return res.ToIPv4AddressSection(), err
}

func (section *IPv4AddressSection) ReverseBytes() *IPv4AddressSection {
	return section.ReverseSegments()
}

//func (section *IPv4AddressSection) ReverseBytesPerSegment() *IPv4AddressSection {
//	if !section.IsPrefixed() {
//		return section
//	}
//	return section.WithoutPrefixLen()
//}

func (section *IPv4AddressSection) ReverseSegments() *IPv4AddressSection {
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
	return res.ToIPv4AddressSection()
}

var (
	ipv4CanonicalParams          = NewIPv4StringOptionsBuilder().ToOptions()
	ipv4FullParams               = NewIPv4StringOptionsBuilder().SetExpandedSegments(true).SetWildcardOptions(wildcardsRangeOnlyNetworkOnly).ToOptions()
	ipv4NormalizedWildcardParams = NewIPv4StringOptionsBuilder().SetWildcardOptions(allWildcards).ToOptions()
	ipv4SqlWildcardParams        = NewIPv4StringOptionsBuilder().SetWildcardOptions(allSQLWildcards).ToOptions()

	inetAtonOctalParams       = NewIPv4StringOptionsBuilder().SetRadix(Inet_aton_radix_octal.GetRadix()).SetSegmentStrPrefix(Inet_aton_radix_octal.GetSegmentStrPrefix()).ToOptions()
	inetAtonHexParams         = NewIPv4StringOptionsBuilder().SetRadix(Inet_aton_radix_hex.GetRadix()).SetSegmentStrPrefix(Inet_aton_radix_hex.GetSegmentStrPrefix()).ToOptions()
	ipv4ReverseDNSParams      = NewIPv4StringOptionsBuilder().SetWildcardOptions(allWildcards).SetReverse(true).SetAddressSuffix(IPv4ReverseDnsSuffix).ToOptions()
	ipv4SegmentedBinaryParams = new(IPStringOptionsBuilder).SetRadix(2).SetSeparator(IPv4SegmentSeparator).SetSegmentStrPrefix(BinaryPrefix).ToOptions()
)

// ToCanonicalString produces a canonical string.
//
//If this section has a prefix length, it will be included in the string.
func (section *IPv4AddressSection) ToCanonicalString() string {
	return cacheStr(&section.getStringCache().canonicalString,
		func() string {
			return section.toNormalizedString(ipv4CanonicalParams)
		})
}

// ToNormalizedString produces a normalized string.
//
//If this section has a prefix length, it will be included in the string.
func (section *IPv4AddressSection) ToNormalizedString() string {
	return section.ToCanonicalString()
}

func (section *IPv4AddressSection) ToCompressedString() string {
	return section.ToCanonicalString()
}

func (section *IPv4AddressSection) ToNormalizedWildcardString() string {
	return cacheStr(&section.getStringCache().normalizedWildcardString,
		func() string {
			return section.toNormalizedString(ipv4NormalizedWildcardParams)
		})
}

func (section *IPv4AddressSection) ToCanonicalWildcardString() string {
	return section.ToNormalizedWildcardString()
}

func (section *IPv4AddressSection) ToSegmentedBinaryString() string {
	return cacheStr(&section.getStringCache().segmentedBinaryString,
		func() string {
			return section.toNormalizedString(ipv4SegmentedBinaryParams)
		})
}

func (section *IPv4AddressSection) ToSQLWildcardString() string {
	return cacheStr(&section.getStringCache().sqlWildcardString,
		func() string {
			return section.toNormalizedString(ipv4SqlWildcardParams)
		})
}

func (section *IPv4AddressSection) ToFullString() string {
	return cacheStr(&section.getStringCache().fullString,
		func() string {
			return section.toNormalizedString(ipv4FullParams)
		})
}

func (section *IPv4AddressSection) ToReverseDNSString() string {
	return cacheStr(&section.getStringCache().reverseDNSString,
		func() string {
			return section.toNormalizedString(ipv4ReverseDNSParams)
		})
}

func (section *IPv4AddressSection) ToPrefixLenString() string {
	return section.ToCanonicalString()
}

func (section *IPv4AddressSection) ToSubnetString() string {
	return section.ToNormalizedWildcardString()
}

func (section *IPv4AddressSection) ToCompressedWildcardString() string {
	return section.ToNormalizedWildcardString()
}

func (section *IPv4AddressSection) ToInetAtonString(radix Inet_aton_radix) string {
	if radix == Inet_aton_radix_octal {
		return cacheStr(&section.getStringCache().inetAtonOctalString,
			func() string {
				return section.toNormalizedString(inetAtonOctalParams)
			})
	} else if radix == Inet_aton_radix_hex {
		return cacheStr(&section.getStringCache().inetAtonHexString,
			func() string {
				return section.toNormalizedString(inetAtonHexParams)
			})
	} else {
		return section.ToCanonicalString()
	}
}

func (section *IPv4AddressSection) ToInetAtonJoinedString(radix Inet_aton_radix, joinedCount int) (string, IncompatibleAddressError) {
	if joinedCount <= 0 {
		return section.ToInetAtonString(radix), nil
	}
	var stringParams IPStringOptions
	if radix == Inet_aton_radix_octal {
		stringParams = inetAtonOctalParams
	} else if radix == Inet_aton_radix_hex {
		stringParams = inetAtonHexParams
	} else {
		stringParams = ipv4CanonicalParams
	}
	return section.ToNormalizedJoinedString(stringParams, joinedCount)
}

func (section *IPv4AddressSection) ToNormalizedJoinedString(stringParams IPStringOptions, joinedCount int) (string, IncompatibleAddressError) {
	if joinedCount <= 0 || section.GetSegmentCount() <= 1 {
		return section.toNormalizedString(stringParams), nil
	}
	equivalentPart, err := section.ToJoinedSegments(joinedCount) // AddressDivisionSeries
	if err != nil {
		return "", err
	}
	return toNormalizedIPString(stringParams, equivalentPart), nil
}

func (section *IPv4AddressSection) ToJoinedSegments(joinCount int) (AddressDivisionSeries, IncompatibleAddressError) {
	thisCount := section.GetSegmentCount()
	if joinCount <= 0 || thisCount <= 1 {
		return section, nil
	}
	var totalCount int
	if joinCount >= thisCount {
		joinCount = thisCount - 1
		totalCount = 1
	} else {
		totalCount = thisCount - joinCount
	}
	joinedSegment, err := section.joinSegments(joinCount) //IPv4JoinedSegments
	if err != nil {
		return nil, err
	}
	notJoinedCount := totalCount - 1
	segs := make([]*AddressDivision, totalCount)
	section.copySubSegmentsToSlice(0, notJoinedCount, segs)
	segs[notJoinedCount] = joinedSegment
	equivalentPart := createInitializedGrouping(segs, section.GetPrefixLength(), zeroType, 0)
	//IPAddressDivisionGrouping equivalentPart = new IPAddressDivisionGrouping(segs, getNetwork());
	return equivalentPart, nil
	//createInitializedGrouping
}

func (section *IPv4AddressSection) joinSegments(joinCount int) (*AddressDivision, IncompatibleAddressError) {
	//  it seems IPv4JoinedSegments override getMaxDigitCount, getBitCount, some others
	// the design I used was intended to handle IPAddressLargeDivision and other such impls like this
	// So I guess this must be passed in as AddressDivisionSeries/GenericDivision
	// We moved a lot of the string methods into stringwriter, wrapping GenericDivision, such as getLowerStandardString
	// And those methods no longer operate on virtual methods of the target GenericDivision, instead they are top-down interface impl calls
	//  so we do need those methods in our joined segment type, but should be fine once they're there

	//xxxx
	//ok, I think I need to supply my own divisionValues
	//
	//either that or I override a lot of stuff, inlcuding getDivisionValue and getUpperDivisionValue and getBitCount
	//
	//I think it makes the most sense to supply my own divisionValues, why supply ipv4 divisionValues that do not apply then override?
	//
	//Once that is done, do I need to override anything?  no
	//xxx
	var lower, upper DivInt
	var prefix PrefixLen
	var networkPrefixLength BitCount

	var firstRange *IPv4AddressSegment
	firstJoinedIndex := section.GetSegmentCount() - 1 - joinCount
	bitsPerSeg := section.GetBitsPerSegment()
	for j := 0; j <= joinCount; j++ {
		thisSeg := section.GetSegment(firstJoinedIndex + j)
		if firstRange != nil {
			if !thisSeg.IsFullRange() {
				return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.segmentMismatch"}}
			}
		} else if thisSeg.isMultiple() {
			firstRange = thisSeg
		}
		lower = (lower << uint(bitsPerSeg)) | DivInt(thisSeg.getSegmentValue())
		upper = (upper << uint(bitsPerSeg)) | DivInt(thisSeg.getUpperSegmentValue())
		if prefix == nil {
			thisSegPrefix := thisSeg.getDivisionPrefixLength()
			if thisSegPrefix != nil {
				prefix = cacheBitCount(networkPrefixLength + *thisSegPrefix)
			} else {
				networkPrefixLength += thisSeg.getBitCount()
			}
		}
	}
	return NewRangePrefixDivision(lower, upper, prefix, (BitCount(joinCount)+1)<<3, IPv4DefaultTextualRadix), nil
}

func (section *IPv4AddressSection) toNormalizedString(stringOptions IPStringOptions) string {
	return toNormalizedIPString(stringOptions, section)
}

type Inet_aton_radix int

func (rad Inet_aton_radix) GetRadix() int {
	return int(rad)
}

func (rad Inet_aton_radix) GetSegmentStrPrefix() string {
	if rad == Inet_aton_radix_octal {
		return OctalPrefix
	} else if rad == Inet_aton_radix_hex {
		return HexPrefix
	}
	return ""
}

func (rad Inet_aton_radix) String() string {
	if rad == Inet_aton_radix_octal {
		return "octal"
	} else if rad == Inet_aton_radix_hex {
		return "hexadecimal"
	}
	return "decimal"
}

const (
	Inet_aton_radix_octal   Inet_aton_radix = 8
	Inet_aton_radix_hex     Inet_aton_radix = 16
	Inet_aton_radix_decimal Inet_aton_radix = 10
)
