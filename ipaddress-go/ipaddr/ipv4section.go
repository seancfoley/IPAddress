package ipaddr

import (
	"math/big"
	"unsafe"
)

func createIPv4Section(segments []*AddressDivision) *IPv4AddressSection {
	return &IPv4AddressSection{
		ipAddressSectionInternal{
			addressSectionInternal{
				addressDivisionGroupingInternal{
					divisions: segments,
					cache:     &valueCache{},
					addrType:  ipv4Type,
				},
			},
		},
	}
}

// error returned for invalid segment count, nil sements, segments with invalid bit size, or inconsistent prefixes
func newIPv4AddressSection(segments []*AddressDivision /*cloneSegments bool,*/, normalizeSegments bool) (res *IPv4AddressSection, err AddressValueException) {
	//if startIndex < 0 {
	//	err = &addressPositionException{val: startIndex, key: "ipaddress.error.invalid.position"}
	//	return
	//}
	segsLen := len(segments)
	if segsLen > IPv4SegmentCount {
		err = &addressValueException{val: segsLen, key: "ipaddress.error.exceeds.size"}
		return
	}
	//if cloneSegments { //TODO this is likely not necessary because for public you will need to convert from []*IPv4AddressSegment to []*AddressDivision before calling this func
	//	segments = append(make([]*AddressDivision, 0, segsLen), segments...)
	//}
	res = createIPv4Section(segments)
	if err = res.init(); err != nil {
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

func newIPv4AddressSectionSingle(segments []*AddressDivision /* cloneSegments bool,*/, prefixLength PrefixLen, singleOnly bool) (res *IPv4AddressSection, err AddressValueException) {
	res, err = newIPv4AddressSection(segments /*cloneSegments,*/, prefixLength == nil)
	if err == nil && prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIPAddressSection(), singleOnly, BitCount(len(segments)<<3), IPv4BitCount)
	}
	return
}

func NewIPv4AddressSectionFromBytes(bytes []byte) (res *IPv4AddressSection, err AddressValueException) {
	return newIPv4AddressSectionFromBytes(bytes, len(bytes), nil, false)
}

// Useful if the byte array has leading zeros or leading sign extension
func NewIPv4AddressSectionFromSegmentedBytes(bytes []byte, segmentCount int) (res *IPv4AddressSection, err AddressValueException) {
	return newIPv4AddressSectionFromBytes(bytes, segmentCount, nil, false)
}

func NewIPv4AddressSectionFromPrefixedBytes(bytes []byte, segmentCount int, prefixLength PrefixLen) (res *IPv4AddressSection, err AddressValueException) {
	return newIPv4AddressSectionFromBytes(bytes, segmentCount, prefixLength, false)
}

func newIPv4AddressSectionFromBytes(bytes []byte, segmentCount int, prefixLength PrefixLen /* boolean cloneBytes,*/, singleOnly bool) (res *IPv4AddressSection, err AddressValueException) {
	if segmentCount < 0 {
		segmentCount = len(bytes)
	}
	segments, err := toSegments(
		bytes,
		segmentCount,
		IPv4BytesPerSegment,
		IPv4BitsPerSegment,
		DefaultIPv4Network.GetIPv4AddressCreator(),
		prefixLength)
	if err == nil {
		res = createIPv4Section(segments)
		if prefixLength != nil {
			assignPrefix(prefixLength, segments, res.ToIPAddressSection(), singleOnly, BitCount(segmentCount<<3), IPv4BitCount)
		}
		bytes = append(make([]byte, 0, len(bytes)), bytes...) // copy //TODO make sure you only create segmentCount (bytes may be longer, I believe we always chop off the top, see toSegments)
		res.cache.lowerBytes = bytes
		if !res.isMultiple {
			res.cache.upperBytes = bytes
		}
	}
	return
}

func NewIPv4AddressSectionFromValues(vals SegmentValueProvider, segmentCount int) (res *IPv4AddressSection) {
	res = NewIPv4AddressSectionFromPrefixedRangeValues(vals, nil, segmentCount, nil)
	return
}

func NewIPv4AddressSectionFromPrefixedValues(vals SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv4AddressSection) {
	return NewIPv4AddressSectionFromPrefixedRangeValues(vals, nil, segmentCount, prefixLength)
}

func NewIPv4AddressSectionFromRangeValues(vals, upperVals SegmentValueProvider, segmentCount int) (res *IPv4AddressSection) {
	res = NewIPv4AddressSectionFromPrefixedRangeValues(vals, upperVals, segmentCount, nil)
	return
}

func NewIPv4AddressSectionFromPrefixedRangeValues(vals, upperVals SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv4AddressSection) {
	if segmentCount < 0 {
		segmentCount = 0
	}
	segments, isMultiple := createSegments(
		vals, upperVals,
		segmentCount,
		IPv4BitsPerSegment,
		DefaultIPv4Network.GetIPv4AddressCreator(),
		prefixLength)
	res = createIPv4Section(segments)
	res.isMultiple = isMultiple
	if prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIPAddressSection(), false, BitCount(segmentCount<<3), IPv4BitCount)
	}
	return
}

// IPv4AddressSection represents a section of an IPv4 address comprising 0 to 4 IPv4 address segments.
// The zero values is a section with zero segments.
type IPv4AddressSection struct {
	ipAddressSectionInternal
}

func (section *IPv4AddressSection) GetCount() *big.Int {
	if !section.IsMultiple() {
		return bigOne()
	}
	return section.cacheCount(func() *big.Int {
		return bigZero().SetUint64(section.GetIPv4Count())
	})
}

func (section *IPv4AddressSection) GetIPv4Count() uint64 {
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

func (section *IPv4AddressSection) Mask(other *IPv4AddressSection) (res *IPv4AddressSection, err error) {
	return section.MaskPrefixed(other, false)
}

func (section *IPv4AddressSection) MaskPrefixed(other *IPv4AddressSection, retainPrefix bool) (res *IPv4AddressSection, err error) {
	sec, err := section.mask(other.ToIPAddressSection(), retainPrefix)
	if err == nil {
		res = sec.ToIPv4AddressSection()
	}
	return
}

func (section *IPv4AddressSection) GetLower() *IPv4AddressSection {
	return section.getLowestOrHighestSection(true).ToIPv4AddressSection()
}

func (section *IPv4AddressSection) GetUpper() *IPv4AddressSection {
	return section.getLowestOrHighestSection(false).ToIPv4AddressSection()
}

func (section *IPv4AddressSection) ToPrefixBlock() *IPv4AddressSection {
	return section.toPrefixBlock().ToIPv4AddressSection()
}

func (section *IPv4AddressSection) ToPrefixBlockLen(prefLen BitCount) *IPv4AddressSection {
	return section.toPrefixBlockLen(prefLen).ToIPv4AddressSection()
}

func (section *IPv4AddressSection) ToIPAddressSection() *IPAddressSection {
	return (*IPAddressSection)(unsafe.Pointer(section))
}

func (section *IPv4AddressSection) GetIPVersion() IPVersion {
	return IPv4
}
