package ipaddr

import (
	"math/big"
	"unsafe"
)

func createIPv6Section(segments []*AddressDivision, startIndex int) *IPv6AddressSection {
	return &IPv6AddressSection{
		ipAddressSectionInternal{
			addressSectionInternal{
				addressDivisionGroupingInternal{
					addressDivisionGroupingBase: addressDivisionGroupingBase{
						divisions: standardDivArray{segments},
						cache:     &valueCache{},
					},
					addrType:            ipv6Type,
					addressSegmentIndex: uint8(startIndex),
				},
			},
		},
	}
}

func newIPv6AddressSection(segments []*AddressDivision, startIndex int /*, cloneSegments bool*/, normalizeSegments bool) (res *IPv6AddressSection, err AddressValueException) {
	if startIndex < 0 {
		err = &addressPositionException{val: startIndex, key: "ipaddress.error.invalid.position"}
		return
	}
	segsLen := len(segments)
	if startIndex+segsLen > IPv6SegmentCount {
		err = &addressValueException{val: startIndex + segsLen, key: "ipaddress.error.exceeds.size"}
		return
	}
	//if cloneSegments { //TODO this is likely not necessary because for public you will need to convert from []*IPv6AddressSegment to []*AddressDivision before calling this func
	//	segments = append(make([]*AddressDivision, 0, segsLen), segments...)
	//}
	res = createIPv6Section(segments, startIndex)
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

func newIPv6AddressSectionSingle(segments []*AddressDivision, startIndex int /*cloneSegments bool,*/, prefixLength PrefixLen, singleOnly bool) (res *IPv6AddressSection, err AddressValueException) {
	res, err = newIPv6AddressSection(segments, startIndex /*cloneSegments,*/, prefixLength == nil)
	if err != nil && prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIPAddressSection(), singleOnly, BitCount(len(segments)<<4), IPv6BitCount)
	}
	return
}

func NewIPv6AddressSectionFromBytes(bytes []byte) (res *IPv6AddressSection, err AddressValueException) {
	return newIPv6AddressSectionFromBytes(bytes, len(bytes), nil, false)
}

// Useful if the byte array has leading zeros or leading sign extension
func NewIPv6AddressSectionFromSegmentedBytes(bytes []byte, segmentCount int) (res *IPv6AddressSection, err AddressValueException) {
	return newIPv6AddressSectionFromBytes(bytes, segmentCount, nil, false)
}

func NewIPv6AddressSectionFromPrefixedBytes(bytes []byte, segmentCount int, prefixLength PrefixLen) (res *IPv6AddressSection, err AddressValueException) {
	return newIPv6AddressSectionFromBytes(bytes, segmentCount, prefixLength, false)
}

func newIPv6AddressSectionFromBytes(bytes []byte, segmentCount int, prefixLength PrefixLen /* boolean cloneBytes,*/, singleOnly bool) (res *IPv6AddressSection, err AddressValueException) {
	if segmentCount < 0 {
		segmentCount = len(bytes)
	}
	segments, err := toSegments(
		bytes,
		segmentCount,
		IPv6BytesPerSegment,
		IPv6BitsPerSegment,
		DefaultIPv6Network.GetIPv6AddressCreator(),
		prefixLength)
	if err == nil {
		res = createIPv6Section(segments, 0)
		if prefixLength != nil {
			assignPrefix(prefixLength, segments, res.ToIPAddressSection(), singleOnly, BitCount(segmentCount<<3), IPv4BitCount)
		}
		bytes = append(make([]byte, 0, len(bytes)), bytes...) // copy //TODO make sure you only create segmentCount (bytes may be longer, I believe we always chop off the top, see toSegments)
		res.cache.lowerBytes = bytes
		res.cache.upperBytes = bytes
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

func (section *IPv6AddressSection) GetCount() *big.Int {
	if !section.IsMultiple() {
		return bigOne()
	}
	return section.cacheCount(func() *big.Int {
		return count(func(index int) uint64 {
			return section.GetSegment(index).GetValueCount()
		}, section.GetSegmentCount(), 2, 0x7fffffffffff)
	})
}

//func (section *IPv6AddressSection) IsMore(other *IPv6AddressSection) int {
//	return section.isMore(other.ToIPAddressSection())
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

//// ForEachSegment calls the given callback for each segment, terminating early if a callback returns true
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

func (section *IPv6AddressSection) Mask(other *IPv6AddressSection) (res *IPv6AddressSection, err error) {
	return section.MaskPrefixed(other, false)
}

func (section *IPv6AddressSection) MaskPrefixed(other *IPv6AddressSection, retainPrefix bool) (res *IPv6AddressSection, err error) {
	sec, err := section.mask(other.ToIPAddressSection(), retainPrefix)
	if err == nil {
		res = sec.ToIPv6AddressSection()
	}
	return
}

func (section *IPv6AddressSection) GetLower() *IPv6AddressSection {
	return section.getLowestOrHighestSection(true).ToIPv6AddressSection()
}

func (section *IPv6AddressSection) GetUpper() *IPv6AddressSection {
	return section.getLowestOrHighestSection(false).ToIPv6AddressSection()
}

func (section *IPv6AddressSection) ToPrefixBlock() *IPv6AddressSection {
	return section.toPrefixBlock().ToIPv6AddressSection()
}

func (section *IPv6AddressSection) ToPrefixBlockLen(prefLen BitCount) *IPv6AddressSection {
	return section.toPrefixBlockLen(prefLen).ToIPv6AddressSection()
}

func (section *IPv6AddressSection) ToIPAddressSection() *IPAddressSection {
	return (*IPAddressSection)(unsafe.Pointer(section))
}

func (section *IPv6AddressSection) GetIPVersion() IPVersion {
	return IPv6
}
