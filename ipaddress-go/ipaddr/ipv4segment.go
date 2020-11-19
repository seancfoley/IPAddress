package ipaddr

import "unsafe"

type ipv4SegmentValues struct {
	value      uint8
	upperValue uint8
	prefLen    PrefixLen
}

func (seg ipv4SegmentValues) GetBitCount() BitCount {
	return IPv4BitsPerSegment
}

func (seg ipv4SegmentValues) GetByteCount() int {
	return IPv4BytesPerSegment
}

func (seg ipv4SegmentValues) GetDivisionValue() DivInt {
	return DivInt(seg.value)
}

func (seg ipv4SegmentValues) GetUpperDivisionValue() DivInt {
	return DivInt(seg.upperValue)
}

func (seg ipv4SegmentValues) getDivisionPrefixLength() PrefixLen {
	return seg.prefLen
}

func (seg ipv4SegmentValues) GetSegmentPrefixLength() PrefixLen {
	return seg.prefLen
}

func (seg ipv4SegmentValues) GetSegmentValue() SegInt {
	return SegInt(seg.value)
}

func (seg ipv4SegmentValues) GetUpperSegmentValue() SegInt {
	return SegInt(seg.upperValue)
}

var _ divisionValues = ipv4SegmentValues{}
var _ segmentValues = ipv4SegmentValues{}

//TODO make this use pointers to, just like sections and addresses, because we will have cached data too,
//isSinglePrefixBlock, cachedString,
//	protected transient String cachedWildcardString;
//	private transient byte[] lowerBytes, upperBytes;
// Now, since the parsing will populate the cachedString, we could move it out of the cached data, which is stuff that is populate on the fly
// But remember, that is a bad idea, we want to allow copying, so anything that is not always created right away must go to cache object

type IPv4AddressSegment struct {
	ipAddressSegmentInternal
}

// We must override GetBitCount, GetByteCount and others for the case when we construct as the zero value

func (seg *IPv4AddressSegment) GetBitCount() BitCount {
	return IPv4BitsPerSegment
}

func (seg *IPv4AddressSegment) GetByteCount() int {
	return IPv4BytesPerSegment
}

func (seg *IPv4AddressSegment) ToAddressDivision() *AddressDivision {
	if seg == nil {
		return nil
	}
	vals := seg.divisionValues
	if vals == nil {
		seg.divisionValues = ipv4SegmentValues{}
	}
	return (*AddressDivision)(unsafe.Pointer(seg))
}

func (seg *IPv4AddressSegment) ToIPAddressSegment() *IPAddressSegment {
	if seg == nil {
		return nil
	}
	vals := seg.divisionValues
	if vals == nil {
		seg.divisionValues = ipv4SegmentValues{}
	}
	return (*IPAddressSegment)(unsafe.Pointer(seg))
}

func NewIPv4Segment(val uint8) *IPv4AddressSegment {
	return NewIPv4RangePrefixSegment(val, val, nil)
}

func NewIPv4RangeSegment(val, upperVal uint8) *IPv4AddressSegment {
	return NewIPv4RangePrefixSegment(val, val, nil)
}

func NewIPv4PrefixSegment(val uint8, prefixLen PrefixLen) *IPv4AddressSegment {
	return NewIPv4RangePrefixSegment(val, val, prefixLen)
}

func NewIPv4RangePrefixSegment(val, upperVal uint8, prefixLen PrefixLen) *IPv4AddressSegment {
	return &IPv4AddressSegment{
		ipAddressSegmentInternal{
			addressSegmentInternal{
				addressDivisionInternal{
					ipv4SegmentValues{
						value:      val,
						upperValue: upperVal,
						prefLen:    prefixLen,
					},
				},
			},
		},
	}
}
