package ipaddr

import (
	"unsafe"
)

func creationIPv4Section(segments []*AddressDivision) *IPv4AddressSection {
	return &IPv4AddressSection{
		ipAddressSectionInternal{
			addressSectionInternal{
				addressDivisionGroupingInternal{
					divisions: segments,
					cache:     &valueCache{},
					//addressSegmentIndex: uint8(startIndex),
					addrType: ipv4Type,
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
	res = creationIPv4Section(segments)
	err = res.init(IPv4BitsPerSegment)
	if err != nil {
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
		err = assignPrefix(prefixLength, segments, res.ToIPAddressSection(), singleOnly, BitCount(len(segments)<<3), IPv4BitCount)
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
		//S segments[],
		bytes,
		segmentCount,
		IPv4BytesPerSegment,
		IPv4BitsPerSegment,
		DefaultIPv4Network.GetIPv4AddressCreator(),
		prefixLength)
	if err == nil {
		res = creationIPv4Section(segments)
		if prefixLength != nil {
			err = assignPrefix(prefixLength, segments, res.ToIPAddressSection(), singleOnly, BitCount(segmentCount<<3), IPv4BitCount)
		}
		if err == nil {
			bytes = append(make([]byte, 0, len(bytes)), bytes...) // copy //TODO make sure you only create segmentCount (bytes may be longer, I believe we always chop off the top, see toSegments)
			res.cache.lowerBytes = bytes
			if !res.isMultiple {
				res.cache.upperBytes = bytes
			}
		}
	}
	return
}

func NewIPv4AddressSectionFromValues(vals SegmentValueProvider, segmentCount int) (res *IPv4AddressSection) {
	res, _ = NewIPv4AddressSectionFromPrefixedRangeValues(vals, nil, segmentCount, nil)
	return
}

func NewIPv4AddressSectionFromPrefixedValues(vals SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv4AddressSection, err AddressValueException) {
	return NewIPv4AddressSectionFromPrefixedRangeValues(vals, nil, segmentCount, prefixLength)
}

func NewIPv4AddressSectionFromRangeValues(vals, upperVals SegmentValueProvider, segmentCount int) (res *IPv4AddressSection) {
	res, _ = NewIPv4AddressSectionFromPrefixedRangeValues(vals, upperVals, segmentCount, nil)
	return
}

func NewIPv4AddressSectionFromPrefixedRangeValues(vals, upperVals SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv4AddressSection, err AddressValueException) {
	if segmentCount < 0 {
		segmentCount = 0
	}
	segments, isMultiple := createSegments(
		//S segments[],
		vals, upperVals,
		segmentCount,
		IPv4BytesPerSegment,
		IPv4BitsPerSegment,
		DefaultIPv4Network.GetIPv4AddressCreator(),
		prefixLength)
	//if err == nil {
	res = creationIPv4Section(segments)
	res.isMultiple = isMultiple
	if prefixLength != nil {
		err = assignPrefix(prefixLength, segments, res.ToIPAddressSection(), false, BitCount(segmentCount<<3), IPv4BitCount)
	}
	//}
	return
}

// IPv4AddressSection represents a section of an IPv4 address comprising 0 to 4 IPv4 address segments.
// The zero values is a section with zero segments.
type IPv4AddressSection struct {
	ipAddressSectionInternal
}

func (section *IPv4AddressSection) GetSegment(index int) *IPv4AddressSegment {
	return section.GetDivision(index).ToIPv4AddressSegment()
}

func (section *IPv4AddressSection) GetLower() *IPv4AddressSection {
	return section.ToAddressSection().GetLower().ToIPv4AddressSection()
}

func (section *IPv4AddressSection) GetUpper() *IPv4AddressSection {
	return section.ToAddressSection().GetUpper().ToIPv4AddressSection()
}

func (section *IPv4AddressSection) ToPrefixBlock() *IPv4AddressSection {
	//TODO ToPrefixBlock
	return nil
}

func (section *IPv4AddressSection) ToIPAddressSection() *IPAddressSection {
	return (*IPAddressSection)(unsafe.Pointer(section))
}

func (section *IPv4AddressSection) GetIPVersion() IPVersion {
	return IPv4
}
